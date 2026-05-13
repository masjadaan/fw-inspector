#!/usr/bin/env python3
"""
Builds a typed entity-relationship graph from attack_surface.json.

Entities:  Firmware, Binary, Service, Port, Config, Credential, Certificate,
           FilesystemObject, ProcessContext, CryptoPrimitive, Weakness,
           WeaknessClass, TrustZone

Relationships: PROVIDES, EXPOSES, LISTENS_ON, RUNS_AS, LOADS_CONFIG,
               CONTAINS_SECRET, LINKS_TO, REACHABLE_FROM, DEPENDS_ON,
               USES_CRYPTO, ASSOCIATED_WITH, EXPOSES_WEAKNESS

Every node and edge carries a provenance block:
    { "type": "extracted|inferred|hypothesized", "source": str, "confidence": float }

Attack paths are derived algorithmically from graph traversal — never authored manually.

Usage:
    python3 graph.py Archer_A5V6_attack_surface.json
    python3 graph.py Archer_A5V6_attack_surface.json --dot
    python3 graph.py Archer_A5V6_attack_surface.json --output my_graph.json
"""

import argparse
import json
import re
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA_VERSION = "1.0"

# Stable UUID namespace — same input always produces the same node ID
_NS = uuid.UUID("b1e2c3d4-e5f6-7890-abcd-ef1234567890")

EXTRACTED    = "extracted"
INFERRED     = "inferred"
HYPOTHESIZED = "hypothesized"


# ── Helpers ───────────────────────────────────────────────────────────────────

def mkid(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "|".join(str(p) for p in parts)))


def prov(type_: str, source: str, confidence: float) -> dict:
    return {"type": type_, "source": source, "confidence": round(confidence, 2)}


def strip_rootfs(path: str) -> str:
    for prefix in (
        "/output/extracted/rootfs/squashfs-root",
        "/output/extracted/rootfs",
    ):
        if path.startswith(prefix):
            return path[len(prefix):] or "/"
    return path


# ── Trust zone table ──────────────────────────────────────────────────────────

_TRUST_ZONES = {
    "WAN":   "Internet-facing, untrusted external network",
    "LAN":   "Local area network, semi-trusted (router admin interface side)",
    "LOCAL": "Device-local: loopback, unix sockets, IPC",
}

# Ports whose primary exposure is WAN on a home router (ISP-facing services)
_WAN_SERVICES = {"tr069", "cwmp"}
_WAN_PORTS    = {7547, 8069}


def zone_for(port_num: int, svc_type: str) -> str:
    if port_num in _WAN_PORTS or svc_type.lower() in _WAN_SERVICES:
        return "WAN"
    return "LAN"


# ── Crypto knowledge table ────────────────────────────────────────────────────

_CRYPTO_CWE = {
    "DES":  ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "3DES": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "RC2":  ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "RC4":  ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "MD4":  ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "MD5":  ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
}

# Binary hardening check key → (CWE-ID, description)
_HARDENING_WEAKNESSES: dict[str, tuple[str, str]] = {
    "nx_disabled":   ("CWE-693", "NX/DEP disabled — stack and heap pages are executable; shellcode injection possible"),
    "relro_none":    ("CWE-693", "No RELRO — GOT/PLT is writable at runtime; GOT-overwrite attack is possible"),
    "relro_partial": ("CWE-693", "Partial RELRO only — lazy binding leaves PLT GOT writable after startup"),
    "canary_no":     ("CWE-121", "No stack canary — stack-smashing buffer overflows are not detected at runtime"),
    "pie_no":        ("CWE-693", "Not PIE — fixed load address weakens ASLR; ROP chains are easier to construct"),
}

# Severity per check (used when scoring attack paths)
_HARDENING_SEVERITY: dict[str, str] = {
    "nx_disabled":   "high",
    "relro_none":    "medium",
    "relro_partial": "low",
    "canary_no":     "high",
    "pie_no":        "medium",
}

# Numeric weight per severity level — used to score weakness contribution in attack paths
_SEV_WEIGHT: dict[str, float] = {"high": 2.0, "medium": 1.0, "low": 0.5}

# ShellCheck code → (CWE-ID, description) for security-relevant codes only
_SC_CWE: dict[int, tuple[str, str]] = {
    2059: ("CWE-134", "Variable used as printf format string — format string injection"),
    2086: ("CWE-20",  "Unquoted variable subject to word splitting on attacker-controlled input"),
    2046: ("CWE-20",  "Unquoted command substitution — word splitting on attacker-controlled input"),
    2091: ("CWE-78",  "Executing result of expression — OS command injection vector"),
}

# Ordered: longest-prefix first to avoid misclassifying DES_ede3 as plain DES
_SYM_ALGO = [
    ("DES_ede3", "3DES"),
    ("DES_",     "DES"),
    ("RC2_",     "RC2"),
    ("RC4_",     "RC4"),
    ("MD4_",     "MD4"),
    ("md5_",     "MD5"),
    ("MD5_",     "MD5"),
]


def sym_to_algo(symbol: str) -> str | None:
    for prefix, algo in _SYM_ALGO:
        if symbol.startswith(prefix):
            return algo
    return None


# ── Graph ─────────────────────────────────────────────────────────────────────

class Graph:
    """Directed property graph implemented over plain dicts. No external deps."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        # adjacency: out_edges[src] = [(rel, dst)], in_edges[dst] = [(rel, src)]
        self._out:      dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._in:       dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._edge_ids: set[str]                         = set()

    def add_node(self, nid: str, type_: str, attrs: dict, prov_: dict) -> str:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "type": type_, "attributes": attrs,
                               "provenance": prov_}
        return nid

    def add_edge(self, src: str, dst: str, rel: str, attrs: dict, prov_: dict) -> None:
        eid = mkid("edge", src, rel, dst)
        if eid in self._edge_ids:
            return
        self._edge_ids.add(eid)
        self.edges.append({"id": eid, "source": src, "target": dst,
                           "relationship": rel, "attributes": attrs,
                           "provenance": prov_})
        self._out[src].append((rel, dst))
        self._in[dst].append((rel, src))

    def has_edge(self, src: str, dst: str, rel: str | None = None) -> bool:
        return any(
            d == dst and (rel is None or r == rel)
            for r, d in self._out.get(src, [])
        )

    def successors(self, nid: str, rel: str | None = None) -> list[str]:
        return [d for r, d in self._out.get(nid, []) if rel is None or r == rel]

    def predecessors(self, nid: str, rel: str | None = None) -> list[str]:
        return [s for r, s in self._in.get(nid, []) if rel is None or r == rel]

    def reachable(self, start_id: str, follow_rels: set[str] | None = None) -> set[str]:
        """BFS from start_id following outgoing edges (optionally filtered by rel type)."""
        visited: set[str] = set()
        queue = deque([start_id])
        while queue:
            cur = queue.popleft()
            for rel, nxt in self._out.get(cur, []):
                if (follow_rels is None or rel in follow_rels) and nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        return visited


# ── Builder ───────────────────────────────────────────────────────────────────

class GraphBuilder:

    def __init__(self, firmware_id: str) -> None:
        self.firmware_id = firmware_id
        self.g = Graph()

    # ── Trust zones ──────────────────────────────────────────────────────────

    def _build_trust_zones(self) -> dict[str, str]:
        zones: dict[str, str] = {}
        for name, desc in _TRUST_ZONES.items():
            nid = mkid("TrustZone", name)
            self.g.add_node(nid, "TrustZone",
                            {"name": name, "description": desc},
                            prov(EXTRACTED, "schema", 1.0))
            zones[name] = nid
        return zones

    # ── Firmware ─────────────────────────────────────────────────────────────

    def _build_firmware(self, surface: dict) -> str:
        nid = mkid("Firmware", self.firmware_id)
        fw  = surface["firmware"]
        self.g.add_node(nid, "Firmware", {
            "firmware_id": self.firmware_id,
            "analysis_dir": fw.get("analysis_dir", ""),
            "arch":         fw.get("arch", "unknown"),
            "bits":         fw.get("bits", 0),
            "endianness":   fw.get("endianness", "unknown"),
        }, prov(EXTRACTED, "architecture.txt", fw.get("arch_confidence", 1.0)))
        return nid

    # ── Ports, services, binaries from entry_points ───────────────────────────

    def _build_network_layer(
        self, surface: dict, zones: dict[str, str]
    ) -> tuple[dict, dict]:
        port_nids: dict[tuple[int, str], str] = {}
        svc_nids:  dict[str, str]              = {}

        for ep in surface.get("entry_points", []):
            port_num  = ep["port"]
            proto     = ep["protocol"]
            svc_type  = ep["type"]
            bin_path  = ep.get("binary") or svc_type
            interface = ep.get("interface", "unknown")
            source    = ep.get("source", "entry_points")
            confidence = 0.85

            bin_name = Path(bin_path).name if bin_path else svc_type

            # Binary
            bin_nid = mkid("Binary", bin_path)
            self.g.add_node(bin_nid, "Binary", {
                "name": bin_name,
                "path": strip_rootfs(bin_path) if bin_path else None,
            }, prov(EXTRACTED, source, confidence))

            # Service
            svc_nid = mkid("Service", svc_type, str(port_num))
            self.g.add_node(svc_nid, "Service", {
                "name": svc_type,
                "binary": bin_name,
            }, prov(EXTRACTED, source, confidence))
            svc_nids[svc_type] = svc_nid

            # Port
            port_nid = mkid("Port", str(port_num), proto)
            self.g.add_node(port_nid, "Port", {
                "number": port_num,
                "protocol": proto,
                "service_type": svc_type,
                "interface": interface,
            }, prov(EXTRACTED, source, confidence))
            port_nids[(port_num, proto)] = port_nid

            # Edges: Binary -PROVIDES-> Service -EXPOSES-> Port
            self.g.add_edge(bin_nid, svc_nid, "PROVIDES", {},
                            prov(INFERRED, source, 0.8))
            self.g.add_edge(svc_nid, port_nid, "EXPOSES", {},
                            prov(EXTRACTED, source, confidence))

            # Port -REACHABLE_FROM-> TrustZone
            z = zone_for(port_num, svc_type)
            self.g.add_edge(port_nid, zones[z], "REACHABLE_FROM",
                            {"note": "zone assigned by port/service heuristic"},
                            prov(INFERRED, "zone_heuristic", 0.70))

        return port_nids, svc_nids

    # ── Process contexts ──────────────────────────────────────────────────────

    def _build_process_contexts(self, surface: dict, svc_nids: dict[str, str]) -> str:
        # Single shared root context — all router daemons inferred to run as root
        root_nid = mkid("ProcessContext", "root")
        self.g.add_node(root_nid, "ProcessContext", {
            "uid": 0,
            "gid": 0,
            "username": "root",
            "capabilities": "full",
            "note": "Embedded router daemons typically run as root",
        }, prov(INFERRED, "embedded_device_heuristic", 0.75))

        for svc_nid in svc_nids.values():
            self.g.add_edge(svc_nid, root_nid, "RUNS_AS", {},
                            prov(INFERRED, "embedded_device_heuristic", 0.75))

        # SetUID binaries — also RUNS_AS root via elevation
        privesc = surface.get("privilege_escalation", {})
        for path in privesc.get("setuid_binaries", []):
            bin_nid = mkid("Binary", path)
            self.g.add_node(bin_nid, "Binary", {
                "name": Path(path).name,
                "path": strip_rootfs(path),
                "setuid": True,
            }, prov(EXTRACTED, "setuid_binaries.txt", 0.95))
            self.g.add_edge(bin_nid, root_nid, "RUNS_AS",
                            {"via": "setuid"},
                            prov(EXTRACTED, "setuid_binaries.txt", 0.95))

        # Explicit POSIX capabilities from capabilities.txt
        for cap in privesc.get("capabilities", []):
            ctx_nid = mkid("ProcessContext", "cap", cap["path"])
            self.g.add_node(ctx_nid, "ProcessContext", {
                "uid": None,
                "capabilities": cap["capabilities"],
                "path": strip_rootfs(cap["path"]),
            }, prov(EXTRACTED, "capabilities.txt", 0.95))
            bin_nid = mkid("Binary", cap["path"])
            self.g.add_node(bin_nid, "Binary", {
                "name": Path(cap["path"]).name,
                "path": strip_rootfs(cap["path"]),
            }, prov(EXTRACTED, "capabilities.txt", 0.9))
            self.g.add_edge(bin_nid, ctx_nid, "RUNS_AS", {},
                            prov(EXTRACTED, "capabilities.txt", 0.95))

        return root_nid

    # ── Crypto primitives ─────────────────────────────────────────────────────

    def _build_crypto(self, surface: dict) -> None:
        for finding in surface.get("weak_crypto", []):
            for line in finding.get("evidence", []):
                # Line format: "path/to/binary: SYM1, SYM2, ..."
                m = re.match(r"^(.+?):\s+(.+)$", line.strip())
                if not m:
                    continue
                bin_path = m.group(1).strip()
                symbols  = [s.strip() for s in m.group(2).split(",")]

                bin_nid = mkid("Binary", bin_path)
                self.g.add_node(bin_nid, "Binary", {
                    "name": Path(bin_path).name,
                    "path": strip_rootfs(bin_path),
                }, prov(EXTRACTED, "weak_crypto.txt", 0.9))

                algos_done: set[str] = set()
                for sym in symbols:
                    algo = sym_to_algo(sym)
                    if not algo or algo in algos_done:
                        continue
                    algos_done.add(algo)

                    prim_nid = mkid("CryptoPrimitive", algo)
                    if prim_nid not in self.g.nodes:
                        cwe_id, cwe_desc = _CRYPTO_CWE.get(algo, ("", ""))
                        self.g.add_node(prim_nid, "CryptoPrimitive", {
                            "algorithm": algo,
                            "broken": True,
                            "cwe": cwe_id,
                            "cwe_description": cwe_desc,
                        }, prov(EXTRACTED, "schema", 1.0))

                        # Wire primitive to its WeaknessClass
                        if cwe_id:
                            wc_nid = mkid("WeaknessClass", cwe_id)
                            self.g.add_node(wc_nid, "WeaknessClass", {
                                "cwe": cwe_id,
                                "description": cwe_desc,
                            }, prov(EXTRACTED, "schema", 1.0))
                            self.g.add_edge(prim_nid, wc_nid, "ASSOCIATED_WITH", {},
                                            prov(EXTRACTED, "schema", 1.0))

                    syms_for_algo = [s for s in symbols if sym_to_algo(s) == algo]
                    self.g.add_edge(bin_nid, prim_nid, "USES_CRYPTO",
                                    {"symbols": syms_for_algo},
                                    prov(EXTRACTED, "weak_crypto.txt", 0.95))

    # ── Filesystem objects and weaknesses ─────────────────────────────────────

    def _build_fs_and_weaknesses(self, surface: dict) -> None:
        privesc = surface.get("privilege_escalation", {})
        ww      = privesc.get("world_writable", {})

        for path in ww.get("files", []):
            clean = strip_rootfs(path)
            fs_nid = mkid("FilesystemObject", path)
            w_nid  = mkid("Weakness", "world_writable_file", path)
            self.g.add_node(fs_nid, "FilesystemObject", {
                "path": clean, "fs_type": "file",
                "permissions": "world_writable",
            }, prov(EXTRACTED, "world_writable.txt", 0.95))
            self.g.add_node(w_nid, "Weakness", {
                "type": "world_writable_file",
                "path": clean,
                "cwe": "CWE-732",
                "description": "World-writable file — any process can modify or replace it",
                "severity": "medium",
            }, prov(EXTRACTED, "world_writable.txt", 0.95))
            self.g.add_edge(fs_nid, w_nid, "EXPOSES_WEAKNESS", {},
                            prov(EXTRACTED, "world_writable.txt", 0.95))

        for path in ww.get("dirs", []):
            clean = strip_rootfs(path)
            fs_nid = mkid("FilesystemObject", path)
            w_nid  = mkid("Weakness", "world_writable_dir", path)
            self.g.add_node(fs_nid, "FilesystemObject", {
                "path": clean, "fs_type": "directory",
                "permissions": "world_writable",
            }, prov(EXTRACTED, "world_writable.txt", 0.95))
            self.g.add_node(w_nid, "Weakness", {
                "type": "world_writable_directory",
                "path": clean,
                "cwe": "CWE-732",
                "description": "World-writable directory — any process can plant files",
                "severity": "medium",
            }, prov(EXTRACTED, "world_writable.txt", 0.95))
            self.g.add_edge(fs_nid, w_nid, "EXPOSES_WEAKNESS", {},
                            prov(EXTRACTED, "world_writable.txt", 0.95))

        for finding in surface.get("debug_artifacts", []):
            for item in finding.get("items", [])[:10]:
                if ":" in item:
                    # "path:content" lines from grep — extract path
                    raw_path = item.split(":")[0]
                else:
                    raw_path = item
                clean = strip_rootfs(raw_path)
                fs_nid = mkid("FilesystemObject", raw_path)
                w_nid  = mkid("Weakness", "debug_artifact", raw_path)
                self.g.add_node(fs_nid, "FilesystemObject", {
                    "path": clean, "fs_type": "file", "role": "debug",
                }, prov(EXTRACTED, "debug_artifacts.txt", 0.85))
                self.g.add_node(w_nid, "Weakness", {
                    "type": "debug_artifact",
                    "path": clean,
                    "context": finding.get("context", ""),
                    "cwe": "CWE-489",
                    "description": "Debug/test/factory artifact present in production firmware",
                    "severity": "medium",
                }, prov(EXTRACTED, "debug_artifacts.txt", 0.85))
                self.g.add_edge(fs_nid, w_nid, "EXPOSES_WEAKNESS", {},
                                prov(EXTRACTED, "debug_artifacts.txt", 0.85))

    # ── Credentials ───────────────────────────────────────────────────────────

    def _build_credentials(self, surface: dict) -> None:
        creds  = surface.get("credentials", {})
        fw_nid = mkid("Firmware", self.firmware_id)

        for line in creds.get("hardcoded_in_configs", [])[:15]:
            clean = strip_rootfs(line)
            nid = mkid("Credential", "hardcoded", clean)
            self.g.add_node(nid, "Credential", {
                "type": "hardcoded_config",
                "evidence": clean[:200],
                "cwe": "CWE-798",
                "description": "Hardcoded credential or secret in config file",
            }, prov(EXTRACTED, "credentials.txt", 0.80))
            raw_path = line.split(":")[0] if ":" in line else line
            fs_nid = mkid("FilesystemObject", raw_path)
            self.g.add_node(fs_nid, "FilesystemObject", {
                "path": strip_rootfs(raw_path), "fs_type": "file", "role": "config",
            }, prov(EXTRACTED, "credentials.txt", 0.80))
            self.g.add_edge(fs_nid, nid, "CONTAINS_SECRET", {},
                            prov(EXTRACTED, "credentials.txt", 0.80))

        for line in creds.get("default_credentials", [])[:15]:
            clean = line.replace("/output/extracted/rootfs/squashfs-root", "")
            # Detect MD5-crypt shadow hash lines
            if "$1$" in line:
                m = re.search(r"(\w[\w-]*):\$1\$([^:]+)", line)
                if m:
                    username = m.group(1)
                    nid = mkid("Credential", "shadow_md5", username)
                    self.g.add_node(nid, "Credential", {
                        "type": "shadow_hash",
                        "username": username,
                        "hash_algorithm": "MD5-crypt ($1$)",
                        "strength": "WEAK",
                        "cwe": "CWE-916",
                        "description": "MD5-crypt hash is brute-forceable with modern hardware",
                    }, prov(EXTRACTED, "default_credentials.txt", 0.90))
                    shadow_nid = mkid("FilesystemObject", "/etc/shadow")
                    self.g.add_node(shadow_nid, "FilesystemObject", {
                        "path": "/etc/shadow", "fs_type": "file", "role": "shadow",
                    }, prov(EXTRACTED, "default_credentials.txt", 0.90))
                    self.g.add_edge(shadow_nid, nid, "CONTAINS_SECRET", {},
                                    prov(EXTRACTED, "default_credentials.txt", 0.90))
                    continue

            nid = mkid("Credential", "default", clean)
            self.g.add_node(nid, "Credential", {
                "type": "default_credential_reference",
                "evidence": clean[:200],
                "cwe": "CWE-1392",
            }, prov(EXTRACTED, "default_credentials.txt", 0.75))
            raw_path = line.split(":")[0] if ":" in line else None
            if raw_path and raw_path.startswith("/"):
                fs_nid = mkid("FilesystemObject", raw_path)
                self.g.add_node(fs_nid, "FilesystemObject", {
                    "path": strip_rootfs(raw_path), "fs_type": "file",
                }, prov(EXTRACTED, "default_credentials.txt", 0.75))
                self.g.add_edge(fs_nid, nid, "CONTAINS_SECRET", {},
                                prov(EXTRACTED, "default_credentials.txt", 0.75))
            else:
                self.g.add_edge(fw_nid, nid, "CONTAINS_SECRET", {},
                                prov(INFERRED, "default_credentials.txt", 0.65))

        for url in creds.get("cloud_endpoints", [])[:10]:
            clean = strip_rootfs(url)
            nid = mkid("Credential", "cloud_endpoint", clean)
            self.g.add_node(nid, "Credential", {
                "type": "cloud_endpoint",
                "evidence": clean[:200],
                "cwe": "CWE-200",
                "description": "Hardcoded cloud/update endpoint — potential MITM or impersonation target",
            }, prov(EXTRACTED, "credentials.txt", 0.75))
            self.g.add_edge(fw_nid, nid, "CONTAINS_SECRET", {},
                            prov(EXTRACTED, "credentials.txt", 0.75))

    # ── Certificates ──────────────────────────────────────────────────────────

    def _build_certificates(self, surface: dict) -> None:
        certs = surface.get("certificates", {})
        for path in certs.get("files", []):
            nid = mkid("Certificate", path)
            self.g.add_node(nid, "Certificate", {
                "path": strip_rootfs(path),
                "type": "file",
            }, prov(EXTRACTED, "certificates_keys.txt", 0.95))
            fs_nid = mkid("FilesystemObject", path)
            self.g.add_node(fs_nid, "FilesystemObject", {
                "path": strip_rootfs(path), "fs_type": "file", "role": "certificate",
            }, prov(EXTRACTED, "certificates_keys.txt", 0.95))
            self.g.add_edge(fs_nid, nid, "CONTAINS_SECRET", {},
                            prov(EXTRACTED, "certificates_keys.txt", 0.95))

        for line in certs.get("embedded_in_binaries", [])[:10]:
            bin_path = line.split(":")[0] if ":" in line else line
            clean    = strip_rootfs(bin_path)
            nid = mkid("Certificate", "embedded", clean)
            self.g.add_node(nid, "Certificate", {
                "path": clean[:200],
                "type": "embedded",
                "note": "Certificate material embedded in binary or config",
            }, prov(EXTRACTED, "certificates_keys.txt", 0.85))
            bin_nid = mkid("Binary", bin_path)
            self.g.add_node(bin_nid, "Binary", {
                "name": Path(bin_path).name,
                "path": clean,
            }, prov(EXTRACTED, "certificates_keys.txt", 0.85))
            self.g.add_edge(bin_nid, nid, "LINKS_TO", {},
                            prov(EXTRACTED, "certificates_keys.txt", 0.85))

    # ── ShellCheck findings ───────────────────────────────────────────────────

    def _build_shellcheck(self, surface: dict) -> None:
        sc = surface.get("shellcheck", {})
        for fpath, findings in sc.get("by_file", {}).items():
            clean = strip_rootfs(fpath)
            fs_nid = mkid("FilesystemObject", fpath)
            if fs_nid not in self.g.nodes:
                self.g.add_node(fs_nid, "FilesystemObject", {
                    "path": clean, "fs_type": "file", "role": "shell_script",
                }, prov(EXTRACTED, "shellcheck.json", 0.95))

            for finding in findings[:10]:
                code = finding["code"]
                level = finding["level"]
                cwe_id, cwe_desc = _SC_CWE.get(code, ("", f"ShellCheck SC{code}"))
                w_nid = mkid("Weakness", "shellcheck", fpath, str(code))
                self.g.add_node(w_nid, "Weakness", {
                    "type": f"shellcheck_SC{code}",
                    "path": clean,
                    "line": finding["line"],
                    "code": f"SC{code}",
                    "cwe": cwe_id,
                    "cwe_description": cwe_desc,
                    "description": finding["message"],
                    "severity": "high" if level == "error" else "medium",
                }, prov(EXTRACTED, "shellcheck.json", 0.90))
                self.g.add_edge(fs_nid, w_nid, "EXPOSES_WEAKNESS", {},
                                prov(EXTRACTED, "shellcheck.json", 0.90))

    # ── Binary hardening ──────────────────────────────────────────────────────

    def _build_hardening(self, surface: dict) -> None:
        hardening = surface.get("hardening", {})
        binaries  = hardening.get("binaries", [])
        if not binaries:
            return

        # Sort: NX-disabled first (most critical), then canary-missing, then rest.
        # Cap at 100 to keep the graph tractable.
        def _sev_key(b: dict) -> int:
            if b.get("nx") is False:
                return 0
            if b.get("canary") is False:
                return 1
            if b.get("relro") == "none":
                return 2
            return 3

        for binary in sorted(binaries, key=_sev_key)[:100]:
            path = binary.get("path", "")
            if not path:
                continue

            checks = [
                ("nx_disabled",   binary.get("nx") is False),
                ("canary_no",     binary.get("canary") is False),
                ("relro_none",    binary.get("relro") == "none"),
                ("relro_partial", binary.get("relro") == "partial"),
                ("pie_no",        binary.get("pie") == "no"),
            ]
            triggered = [k for k, v in checks if v]
            if not triggered:
                continue

            bin_nid = mkid("Binary", path)
            if bin_nid not in self.g.nodes:
                self.g.add_node(bin_nid, "Binary", {
                    "name": Path(path).name,
                    "path": path,
                }, prov(EXTRACTED, "hardening.json", 0.95))

            for key in triggered:
                cwe_id, desc = _HARDENING_WEAKNESSES[key]
                w_nid = mkid("Weakness", "hardening", path, key)
                self.g.add_node(w_nid, "Weakness", {
                    "type":             key,
                    "path":             path,
                    "cwe":              cwe_id,
                    "cwe_description":  desc,
                    "description":      desc,
                    "severity":         _HARDENING_SEVERITY[key],
                }, prov(EXTRACTED, "hardening.json", 0.95))
                self.g.add_edge(bin_nid, w_nid, "EXPOSES_WEAKNESS", {},
                                prov(EXTRACTED, "hardening.json", 0.95))

    # ── Attack path derivation ────────────────────────────────────────────────

    def derive_attack_paths(self, zones: dict[str, str]) -> list[dict]:
        """
        Derive attack paths by traversing the graph from each TrustZone.

        Algorithm:
          1. For each non-LOCAL zone, find all Port nodes with a REACHABLE_FROM
             edge pointing to that zone.
          2. Walk backward: Port ← EXPOSES ← Service ← PROVIDES ← Binary
          3. Collect context: ProcessContext (RUNS_AS), CryptoPrimitive (USES_CRYPTO),
             Weakness (via FilesystemObject.EXPOSES_WEAKNESS), Credential nodes.
          4. Score severity from zone + privilege + weakness count.

        All returned paths carry provenance.type = 'inferred'.
        """
        paths = []
        g = self.g

        for zone_name, zone_nid in zones.items():
            if zone_name == "LOCAL":
                continue

            # Ports reachable from this zone
            reachable_ports = [
                nid for nid, data in g.nodes.items()
                if data["type"] == "Port" and g.has_edge(nid, zone_nid)
            ]

            for port_nid in reachable_ports:
                port_attrs = g.nodes[port_nid]["attributes"]

                # Services exposing this port
                services = g.predecessors(port_nid, "EXPOSES")
                for svc_nid in services:
                    svc_attrs = g.nodes[svc_nid]["attributes"]

                    # Binaries providing this service
                    binaries = g.predecessors(svc_nid, "PROVIDES")

                    # Process contexts
                    pc_nids = g.successors(svc_nid, "RUNS_AS")
                    runs_as_root = any(
                        g.nodes[n]["attributes"].get("uid") == 0
                        for n in pc_nids
                    )

                    # Crypto weaknesses reachable from any binary in this chain
                    crypto_algos: list[str] = []
                    for bin_nid in binaries:
                        for prim_nid in g.successors(bin_nid, "USES_CRYPTO"):
                            algo = g.nodes[prim_nid]["attributes"].get("algorithm", "")
                            if algo and algo not in crypto_algos:
                                crypto_algos.append(algo)

                    # Weaknesses scoped to binaries in this chain
                    weakness_types: list[str] = []
                    weakness_score: float = 0.0
                    for bin_nid in binaries:
                        for w_nid in g.successors(bin_nid, "EXPOSES_WEAKNESS"):
                            wattrs = g.nodes[w_nid]["attributes"]
                            wt = wattrs.get("type", "")
                            if wt and wt not in weakness_types:
                                weakness_types.append(wt)
                                weakness_score += _SEV_WEIGHT.get(
                                    wattrs.get("severity", "low"), 0.5
                                )

                    # Severity scoring
                    score: float = 0.0
                    if zone_name == "WAN":
                        score += 3
                    elif zone_name == "LAN":
                        score += 1
                    if runs_as_root:
                        score += 3
                    score += min(len(crypto_algos), 2)
                    score += min(weakness_score, 4)

                    if score >= 6:
                        severity = "critical"
                    elif score >= 4:
                        severity = "high"
                    elif score >= 2:
                        severity = "medium"
                    else:
                        severity = "low"

                    path_id = mkid(
                        "AttackPath",
                        zone_name,
                        str(port_attrs["number"]),
                        port_attrs["protocol"],
                        svc_attrs["name"],
                    )

                    paths.append({
                        "id": path_id,
                        "title": (
                            f"{zone_name} → {svc_attrs['name'].upper()} "
                            f":{port_attrs['number']}/{port_attrs['protocol']}"
                        ),
                        "severity": severity,
                        "score": score,
                        "zone": zone_name,
                        "port": port_attrs["number"],
                        "protocol": port_attrs["protocol"],
                        "service": svc_attrs["name"],
                        "runs_as_root": runs_as_root,
                        "crypto_weaknesses": crypto_algos,
                        "structural_weaknesses": weakness_types,
                        "steps": _derive_steps(
                            zone_name, port_attrs, svc_attrs,
                            runs_as_root, crypto_algos,
                        ),
                        "provenance": prov(INFERRED, "graph_traversal", 0.80),
                    })

        _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(paths, key=lambda p: (_SEV_ORDER[p["severity"]], -p["score"]))


def _derive_steps(
    zone: str,
    port_attrs: dict,
    svc_attrs: dict,
    runs_as_root: bool,
    crypto_algos: list[str],
) -> list[str]:
    steps = [
        f"Reach port {port_attrs['number']}/{port_attrs['protocol']} from {zone}",
        f"Interact with {svc_attrs['name']} service",
    ]
    if runs_as_root:
        steps.append(
            "Service runs as root — successful exploitation yields root shell"
        )
    if crypto_algos:
        steps.append(
            f"Binary uses broken cryptography ({', '.join(crypto_algos)}) — "
            "capture and crack session material or forged tokens"
        )
    steps.append("Pivot to further targets or extract credentials/keys from filesystem")
    return steps


# ── Top-level build ───────────────────────────────────────────────────────────

def build(surface: dict, firmware_id: str) -> tuple[Graph, list[dict]]:
    builder = GraphBuilder(firmware_id)
    g       = builder.g

    _fw    = builder._build_firmware(surface)
    zones  = builder._build_trust_zones()
    _ports, svc_nids = builder._build_network_layer(surface, zones)
    _root  = builder._build_process_contexts(surface, svc_nids)

    builder._build_crypto(surface)
    builder._build_fs_and_weaknesses(surface)
    builder._build_credentials(surface)
    builder._build_certificates(surface)
    builder._build_shellcheck(surface)
    builder._build_hardening(surface)

    attack_paths = builder.derive_attack_paths(zones)
    return g, attack_paths


# ── Serialisation ─────────────────────────────────────────────────────────────

def to_dict(g: Graph, attack_paths: list[dict], firmware_id: str) -> dict:
    type_counts: dict[str, int] = {}
    for n in g.nodes.values():
        t = n["type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    rel_counts: dict[str, int] = {}
    for e in g.edges:
        r = e["relationship"]
        rel_counts[r] = rel_counts.get(r, 0) + 1

    return {
        "metadata": {
            "firmware_id": firmware_id,
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "node_count": len(g.nodes),
            "edge_count": len(g.edges),
            "node_type_counts": type_counts,
            "relationship_counts": rel_counts,
        },
        "nodes": list(g.nodes.values()),
        "edges": g.edges,
        "derived_attack_paths": attack_paths,
    }


# ── DOT export ────────────────────────────────────────────────────────────────

_NODE_COLORS = {
    "Firmware":         "#1565c0",
    "Binary":           "#6a1b9a",
    "Service":          "#2e7d32",
    "Port":             "#e65100",
    "Config":           "#546e7a",
    "Credential":       "#c62828",
    "Certificate":      "#f57f17",
    "FilesystemObject": "#00695c",
    "ProcessContext":   "#4527a0",
    "CryptoPrimitive":  "#ad1457",
    "Weakness":         "#bf360c",
    "WeaknessClass":    "#e65100",
    "TrustZone":        "#212121",
}

_EDGE_STYLES = {
    "PROVIDES":         "solid",
    "EXPOSES":          "solid",
    "RUNS_AS":          "dashed",
    "REACHABLE_FROM":   "bold",
    "USES_CRYPTO":      "dashed",
    "ASSOCIATED_WITH":  "dotted",
    "EXPOSES_WEAKNESS": "solid",
    "CONTAINS_SECRET":  "dashed",
    "LINKS_TO":         "dotted",
    "LOADS_CONFIG":     "dashed",
}


def _dot_label(t: str, attrs: dict) -> str:
    """Build a meaningful, type-specific label for a DOT node."""
    def trunc(s: str, n: int = 32) -> str:
        s = str(s).replace('"', "'").replace("\\", "/")
        return s if len(s) <= n else "…" + s[-(n - 1):]

    if t == "Firmware":
        fid    = attrs.get("firmware_id", "Firmware")
        arch   = attrs.get("arch", "")
        bits   = attrs.get("bits", "")
        endian = attrs.get("endianness", "")
        if arch and arch != "unknown":
            return f"{fid}\n{arch} {bits}-bit\n{endian}"
        return fid

    if t == "TrustZone":
        return attrs.get("name", "TrustZone")

    if t == "Binary":
        return f"{attrs.get('name', '?')}\n{trunc(attrs.get('path', ''), 30)}"

    if t == "Service":
        return f"{attrs.get('name', '?')}\n({attrs.get('binary', '')})"

    if t == "Port":
        return f":{attrs.get('number', '?')}/{attrs.get('protocol', '?')}\n{attrs.get('service_type', '')}"

    if t == "ProcessContext":
        uid  = attrs.get("uid", "?")
        uname = attrs.get("username", "")
        caps  = attrs.get("capabilities", "")
        return f"uid={uid} ({uname})\ncaps={caps}"

    if t == "CryptoPrimitive":
        cwe = attrs.get("cwe", "")
        return f"{attrs.get('algorithm', '?')}\n{cwe}"

    if t == "WeaknessClass":
        cwe  = attrs.get("cwe", "?")
        desc = trunc(attrs.get("description", ""), 30)
        return f"{cwe}\n{desc}"

    if t == "FilesystemObject":
        path  = trunc(attrs.get("path", "?"), 32)
        extra = attrs.get("permissions") or attrs.get("role") or ""
        return f"{path}\n{extra}" if extra else path

    if t == "Weakness":
        cwe   = attrs.get("cwe", "?")
        wtype = attrs.get("type", "")
        path  = trunc(attrs.get("path", ""), 30)
        return f"{cwe} {wtype}\n{path}"

    if t == "Credential":
        ctype = attrs.get("type", "credential")
        cwe   = attrs.get("cwe", "")
        if ctype == "shadow_hash":
            uname = attrs.get("username", "?")
            algo  = attrs.get("hash_algorithm", "")
            strength = attrs.get("strength", "")
            return f"{uname} ({algo})\n{strength} {cwe}"
        # default_credential_reference — evidence is "filepath:line_content"
        evidence = attrs.get("evidence", "")
        filepath = evidence.split(":")[0] if evidence else ""
        return f"{trunc(ctype, 28)}\n{trunc(filepath, 32)}\n{cwe}"

    if t == "Certificate":
        path  = trunc(attrs.get("path", "?"), 32)
        ctype = attrs.get("type", "")
        return f"{path}\n{ctype}"

    # fallback
    return attrs.get("name") or attrs.get("algorithm") or attrs.get("username") or t


def to_dot(g: Graph, firmware_id: str) -> str:
    lines = [
        "digraph AttackSurface {",
        f'  label="{firmware_id} — Attack Surface Graph";',
        '  graph [rankdir=LR fontname="Helvetica" bgcolor="#1a1a2e" '
        'labelfontcolor=white fontcolor=white];',
        '  node [style=filled fontname="Helvetica" fontsize=10 fontcolor=white shape=box];',
        '  edge [fontname="Helvetica" fontsize=8 fontcolor="#aaaaaa" color="#666666"];',
        "",
    ]

    for nid, data in g.nodes.items():
        t     = data["type"]
        attrs = data["attributes"]
        label = _dot_label(t, attrs).replace('"', "'")
        conf  = data["provenance"]["confidence"]
        ptype = data["provenance"]["type"][0].upper()     # E / I / H
        color = _NODE_COLORS.get(t, "#555555")
        lines.append(
            f'  "{nid}" [label="{t}\\n{label}\\n[{ptype}:{conf}]" '
            f'fillcolor="{color}"];'
        )

    lines.append("")
    for e in g.edges:
        rel   = e["relationship"]
        style = _EDGE_STYLES.get(rel, "solid")
        conf  = e["provenance"]["confidence"]
        lines.append(
            f'  "{e["source"]}" -> "{e["target"]}" '
            f'[label="{rel}\\n[{conf}]" style={style}];'
        )

    lines.append("}")
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a typed entity-relationship graph from attack_surface.json."
    )
    parser.add_argument(
        "surface_json",
        type=Path,
        help="attack_surface.json produced by surface.py",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output JSON path (default: <firmware_id>_graph.json)",
    )
    parser.add_argument(
        "--dot",
        action="store_true",
        help="Also write a Graphviz DOT file alongside the JSON",
    )
    args = parser.parse_args()

    surface_path = args.surface_json.resolve()
    if not surface_path.exists():
        print(f"[!] File not found: {surface_path}")
        raise SystemExit(1)

    surface     = json.loads(surface_path.read_text())
    firmware_id = surface["firmware"]["id"]

    print(f"[*] Building entity-relationship graph — {firmware_id}")
    g, attack_paths = build(surface, firmware_id)

    out_path = args.output or surface_path.parent / "graph.json"
    result   = to_dict(g, attack_paths, firmware_id)
    out_path.write_text(json.dumps(result, indent=2))

    meta = result["metadata"]
    print(f"[+] Graph written → {out_path}")
    print()
    print(f"    Nodes : {meta['node_count']}")
    for t, n in sorted(meta["node_type_counts"].items()):
        print(f"              {t:<22} {n}")
    print(f"    Edges : {meta['edge_count']}")
    for r, n in sorted(meta["relationship_counts"].items()):
        print(f"              {r:<22} {n}")
    print()
    print(f"    Derived attack paths : {len(attack_paths)}")
    sev_icon = {"critical": "!!!", "high": "!! ", "medium": "!  ", "low": "   "}
    for p in attack_paths:
        icon = sev_icon.get(p["severity"], "   ")
        print(f"      [{icon}] [{p['severity'].upper():<8}] {p['title']}")

    if args.dot:
        dot_path = out_path.with_suffix(".dot")
        dot_path.write_text(to_dot(g, firmware_id))
        print(f"\n[+] DOT written → {dot_path}")
        print(f"    Render: dot -Tsvg {dot_path} -o {dot_path.with_suffix('.svg')}")


if __name__ == "__main__":
    main()
