"""Build the entity-relationship graph and derive attack paths by graph traversal."""

import re
from pathlib import Path

from core import (
    EXTRACTED, INFERRED,
    Graph,
    _CERT_ISSUE_CWE, _CRED_EXPOSURE_WEIGHT, _CRYPTO_CWE, _DANGEROUS_FUNC_CWE,
    _HARDENING_SEVERITY, _HARDENING_WEAKNESSES, _INVALID_SHELLS, _PROTOCOL_META,
    _SC_CWE, _SEV_WEIGHT, _SHELL_AUTH_SERVICES,
    _TLS_ISSUE_CWE, _TLS_ISSUE_DEFAULT, _TRUST_ZONES,
    mkid, prov, resolve_hash_algo, strip_rootfs, sym_to_algo, zone_for,
)


# ── Attack step narrative ─────────────────────────────────────────────────────

def _derive_steps(
    zone: str,
    port_attrs: dict,
    svc_attrs: dict,
    runs_as_root: bool,
    crypto_algos: list[str],
    weak_auth_users: list[str] | None = None,
    dangerous_funcs: list[str] | None = None,
    cert_issues: list[str] | None = None,
    exposed_cred_types: list[str] | None = None,
) -> list[str]:
    steps = [
        f"Reach port {port_attrs['number']}/{port_attrs['protocol']} from {zone}",
        f"Interact with {svc_attrs['name']} service",
    ]
    if runs_as_root:
        steps.append("Service runs as root — successful exploitation yields root shell")
    if crypto_algos:
        steps.append(
            f"Binary uses broken cryptography ({', '.join(crypto_algos)}) — "
            "capture and crack session material or forged tokens"
        )
    if weak_auth_users:
        users_str = ", ".join(f"'{u}'" for u in weak_auth_users[:3])
        steps.append(
            f"Auth backend uses weak password hash (MD5-crypt) for user(s) {users_str} — "
            "offline brute-force yields plaintext credentials"
        )
    if dangerous_funcs:
        fn_str = ", ".join(f"{f}()" for f in dangerous_funcs[:4])
        steps.append(
            f"Binary imports dangerous functions ({fn_str}) — "
            "memory corruption or command injection may allow pre-auth exploitation"
        )
    if cert_issues:
        issue_str = ", ".join(cert_issues[:3])
        steps.append(
            f"Certificate issues ({issue_str}) on linked cert — "
            "MITM is possible; intercepted sessions are not integrity-protected"
        )
    if exposed_cred_types:
        steps.append(
            "Hardcoded or default credentials present in firmware — "
            "static passwords enable credential stuffing or direct login"
        )
    steps.append("Pivot to further targets or extract credentials/keys from filesystem")
    return steps


# ── Graph builder ─────────────────────────────────────────────────────────────

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

    # ── Firmware node ─────────────────────────────────────────────────────────

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
            port_num   = ep["port"]
            proto      = ep["protocol"]
            svc_type   = ep["type"]
            bin_path   = ep.get("binary") or svc_type
            interface  = ep.get("interface", "unknown")
            source     = ep.get("source", "entry_points")
            confidence = 0.85

            bin_name = Path(bin_path).name if bin_path else svc_type

            bin_nid = mkid("Binary", bin_path)
            self.g.add_node(bin_nid, "Binary", {
                "name": bin_name,
                "path": strip_rootfs(bin_path) if bin_path else None,
            }, prov(EXTRACTED, source, confidence))

            svc_nid = mkid("Service", svc_type, str(port_num))
            self.g.add_node(svc_nid, "Service", {
                "name": svc_type,
                "binary": bin_name,
            }, prov(EXTRACTED, source, confidence))
            svc_nids[svc_type] = svc_nid

            port_nid = mkid("Port", str(port_num), proto)
            self.g.add_node(port_nid, "Port", {
                "number": port_num,
                "protocol": proto,
                "service_type": svc_type,
                "interface": interface,
            }, prov(EXTRACTED, source, confidence))
            port_nids[(port_num, proto)] = port_nid

            self.g.add_edge(bin_nid, svc_nid, "PROVIDES", {},
                            prov(INFERRED, source, 0.8))
            self.g.add_edge(svc_nid, port_nid, "EXPOSES", {},
                            prov(EXTRACTED, source, confidence))

            z = zone_for(port_num, svc_type)
            self.g.add_edge(port_nid, zones[z], "REACHABLE_FROM",
                            {"note": "zone assigned by port/service heuristic"},
                            prov(INFERRED, "zone_heuristic", 0.70))

        return port_nids, svc_nids

    # ── Protocol entry points (SNMP / UPnP / TR-069 / MQTT) ──────────────────

    def _build_protocols(self, surface: dict, zones: dict[str, str]) -> dict[str, str]:
        """Add Service/Port nodes for protocols detected in config files.

        Called before _build_network_layer() so these nodes are created with
        evidence from protocols.json first; _build_network_layer() then adds
        the Binary→PROVIDES edge for any protocol that is also in entry_points.
        """
        svc_nids: dict[str, str] = {}
        for proto, info in surface.get("protocols", {}).items():
            if not info.get("present"):
                continue
            if proto not in _PROTOCOL_META:
                continue

            port_num, transport, description = _PROTOCOL_META[proto]
            evidence = info.get("evidence", [])

            svc_nid = mkid("Service", proto, str(port_num))
            self.g.add_node(svc_nid, "Service", {
                "name":        proto,
                "description": description,
                "evidence":    evidence[:3],
            }, prov(EXTRACTED, "protocols.json", 0.75))
            svc_nids[proto] = svc_nid

            port_nid = mkid("Port", str(port_num), transport)
            self.g.add_node(port_nid, "Port", {
                "number":       port_num,
                "protocol":     transport,
                "service_type": proto,
                "interface":    "unknown",
            }, prov(EXTRACTED, "protocols.json", 0.75))

            self.g.add_edge(svc_nid, port_nid, "EXPOSES", {},
                            prov(EXTRACTED, "protocols.json", 0.75))

            z = zone_for(port_num, proto)
            self.g.add_edge(port_nid, zones[z], "REACHABLE_FROM",
                            {"note": "zone assigned by port/service heuristic"},
                            prov(INFERRED, "zone_heuristic", 0.70))

        return svc_nids

    # ── Process contexts ──────────────────────────────────────────────────────

    def _build_process_contexts(self, surface: dict, svc_nids: dict[str, str]) -> str:
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
            clean  = strip_rootfs(path)
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
            clean  = strip_rootfs(path)
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
                raw_path = item.split(":")[0] if ":" in item else item
                clean    = strip_rootfs(raw_path)
                fs_nid   = mkid("FilesystemObject", raw_path)
                w_nid    = mkid("Weakness", "debug_artifact", raw_path)
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
            clean  = strip_rootfs(line)
            nid    = mkid("Credential", "hardcoded", clean)
            self.g.add_node(nid, "Credential", {
                "type": "hardcoded_config",
                "evidence": clean[:200],
                "cwe": "CWE-798",
                "description": "Hardcoded credential or secret in config file",
            }, prov(EXTRACTED, "credentials.txt", 0.80))
            raw_path = line.split(":")[0] if ":" in line else line
            fs_nid   = mkid("FilesystemObject", raw_path)
            self.g.add_node(fs_nid, "FilesystemObject", {
                "path": strip_rootfs(raw_path), "fs_type": "file", "role": "config",
            }, prov(EXTRACTED, "credentials.txt", 0.80))
            self.g.add_edge(fs_nid, nid, "CONTAINS_SECRET", {},
                            prov(EXTRACTED, "credentials.txt", 0.80))

        for line in creds.get("default_credentials", [])[:15]:
            clean = line.replace("/output/extracted/rootfs/squashfs-root", "")
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
            nid   = mkid("Credential", "cloud_endpoint", clean)
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
            nid    = mkid("Certificate", path)
            fs_nid = mkid("FilesystemObject", path)
            self.g.add_node(nid, "Certificate", {
                "path": strip_rootfs(path),
                "type": "file",
            }, prov(EXTRACTED, "certificates_keys.txt", 0.95))
            self.g.add_node(fs_nid, "FilesystemObject", {
                "path": strip_rootfs(path), "fs_type": "file", "role": "certificate",
            }, prov(EXTRACTED, "certificates_keys.txt", 0.95))
            self.g.add_edge(fs_nid, nid, "CONTAINS_SECRET", {},
                            prov(EXTRACTED, "certificates_keys.txt", 0.95))

        for line in certs.get("embedded_in_binaries", [])[:10]:
            bin_path = line.split(":")[0] if ":" in line else line
            clean    = strip_rootfs(bin_path)
            nid      = mkid("Certificate", "embedded", clean)
            bin_nid  = mkid("Binary", bin_path)
            self.g.add_node(nid, "Certificate", {
                "path": clean[:200],
                "type": "embedded",
                "note": "Certificate material embedded in binary or config",
            }, prov(EXTRACTED, "certificates_keys.txt", 0.85))
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
            clean  = strip_rootfs(fpath)
            fs_nid = mkid("FilesystemObject", fpath)
            if fs_nid not in self.g.nodes:
                self.g.add_node(fs_nid, "FilesystemObject", {
                    "path": clean, "fs_type": "file", "role": "shell_script",
                }, prov(EXTRACTED, "shellcheck.json", 0.95))

            for finding in findings[:10]:
                code    = finding["code"]
                level   = finding["level"]
                cwe_id, cwe_desc = _SC_CWE.get(code, ("", f"ShellCheck SC{code}"))
                w_nid   = mkid("Weakness", "shellcheck", fpath, str(code))
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

        def _sev_key(b: dict) -> int:
            if b.get("nx") is False:    return 0
            if b.get("canary") is False: return 1
            if b.get("relro") == "none": return 2
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
                    "type":            key,
                    "path":            path,
                    "cwe":             cwe_id,
                    "cwe_description": desc,
                    "description":     desc,
                    "severity":        _HARDENING_SEVERITY[key],
                }, prov(EXTRACTED, "hardening.json", 0.95))
                self.g.add_edge(bin_nid, w_nid, "EXPOSES_WEAKNESS", {},
                                prov(EXTRACTED, "hardening.json", 0.95))

    # ── Dangerous function imports ────────────────────────────────────────────

    def _build_dangerous_functions(self, surface: dict) -> None:
        for finding in surface.get("dangerous_functions", []):
            bin_path  = finding.get("binary", "")
            functions = finding.get("functions", [])
            if not bin_path or not functions:
                continue

            bin_nid = mkid("Binary", bin_path)
            if bin_nid not in self.g.nodes:
                self.g.add_node(bin_nid, "Binary", {
                    "name": Path(bin_path).name,
                    "path": bin_path,
                }, prov(EXTRACTED, "dangerous_functions.json", 0.90))

            for fn in functions:
                cwe_id, desc, severity = _DANGEROUS_FUNC_CWE.get(
                    fn, ("CWE-676", f"Use of potentially dangerous function {fn}()", "low")
                )
                w_nid = mkid("Weakness", "dangerous_function", bin_path, fn)
                self.g.add_node(w_nid, "Weakness", {
                    "type":        f"dangerous_function_{fn}",
                    "function":    fn,
                    "path":        bin_path,
                    "cwe":         cwe_id,
                    "description": desc,
                    "severity":    severity,
                }, prov(EXTRACTED, "dangerous_functions.json", 0.90))
                self.g.add_edge(bin_nid, w_nid, "EXPOSES_WEAKNESS", {},
                                prov(EXTRACTED, "dangerous_functions.json", 0.90))

    # ── Certificate issues ────────────────────────────────────────────────────

    def _build_certificate_issues(self, surface: dict) -> None:
        for finding in surface.get("certificate_issues", []):
            file_path = finding.get("file", "")
            flags     = finding.get("flags", [])
            if not file_path or not flags:
                continue

            cert_nid = mkid("Certificate", "issue", file_path)
            if cert_nid not in self.g.nodes:
                self.g.add_node(cert_nid, "Certificate", {
                    "path":     file_path,
                    "type":     "file",
                    "subject":  finding.get("subject", ""),
                    "issuer":   finding.get("issuer", ""),
                    "not_after": finding.get("not_after", ""),
                    "key_type": finding.get("key_type", ""),
                    "key_bits": finding.get("key_bits", 0),
                }, prov(EXTRACTED, "certificate_issues.json", 0.95))

            for flag in flags:
                cwe_id, desc, severity = self._resolve_cert_flag(flag)
                safe_flag = flag.split(" ")[0].replace("-", "_")
                w_nid = mkid("Weakness", "certificate_issue", file_path, flag)
                self.g.add_node(w_nid, "Weakness", {
                    "type":        f"certificate_{safe_flag}",
                    "path":        file_path,
                    "flag":        flag,
                    "cwe":         cwe_id,
                    "description": desc,
                    "severity":    severity,
                }, prov(EXTRACTED, "certificate_issues.json", 0.95))
                self.g.add_edge(cert_nid, w_nid, "EXPOSES_WEAKNESS", {},
                                prov(EXTRACTED, "certificate_issues.json", 0.95))

    @staticmethod
    def _resolve_cert_flag(flag: str) -> tuple[str, str, str]:
        for prefix, (cwe_id, desc, severity) in _CERT_ISSUE_CWE.items():
            if flag == prefix or flag.startswith(prefix + " "):
                return cwe_id, desc, severity
        return "CWE-295", f"Certificate issue: {flag}", "medium"

    # ── TLS configuration issues ──────────────────────────────────────────────

    def _build_tls_config_issues(self, surface: dict) -> None:
        for finding in surface.get("tls_config_issues", []):
            file_path = finding.get("file", "")
            issue     = finding.get("issue", "")
            if not file_path or not issue:
                continue

            fs_nid = mkid("FilesystemObject", file_path)
            if fs_nid not in self.g.nodes:
                self.g.add_node(fs_nid, "FilesystemObject", {
                    "path":    file_path,
                    "fs_type": "file",
                    "role":    "tls_config",
                }, prov(EXTRACTED, "tls_config_issues.json", 0.90))

            cwe_id, severity = _TLS_ISSUE_CWE.get(issue, _TLS_ISSUE_DEFAULT)
            line  = finding.get("line", 0)
            w_nid = mkid("Weakness", "tls_config", file_path, issue, str(line))
            self.g.add_node(w_nid, "Weakness", {
                "type":        "tls_config_issue",
                "issue":       issue,
                "path":        file_path,
                "line":        line,
                "cwe":         cwe_id,
                "description": f"Weak TLS/SSL configuration: {issue}",
                "severity":    severity,
                "cve_note":    finding.get("cve_note", ""),
            }, prov(EXTRACTED, "tls_config_issues.json", 0.90))
            self.g.add_edge(fs_nid, w_nid, "EXPOSES_WEAKNESS", {},
                            prov(EXTRACTED, "tls_config_issues.json", 0.90))

    # ── IPC / Unix sockets ────────────────────────────────────────────────────

    def _build_ipc(self, surface: dict) -> None:
        """Add FilesystemObject nodes for Unix socket files (LOCAL zone context)."""
        for path in surface.get("ipc", {}).get("socket_files", []):
            clean = strip_rootfs(path)
            nid   = mkid("FilesystemObject", path)
            if nid not in self.g.nodes:
                self.g.add_node(nid, "FilesystemObject", {
                    "path":    clean,
                    "fs_type": "socket",
                    "role":    "ipc",
                }, prov(EXTRACTED, "unix_sockets.json", 0.90))

    # ── Users and credential links ────────────────────────────────────────────

    def _build_users(self, surface: dict, svc_nids: dict[str, str]) -> None:
        """Create User nodes, link to Credential nodes, and attach AUTHENTICATES_WITH edges.

        For each system user:
          - User node (uid, shell, login_possible)
          - Credential node via HAS_CREDENTIAL (password hash, algo, strength)
          - Weakness node via EXPOSES_WEAKNESS on the Credential if the hash is weak
          - AUTHENTICATES_WITH edges from SSH/Telnet services to login-capable users
        """
        for user in surface.get("users", []):
            name  = user.get("name", "")
            shell = user.get("shell", "")
            if not name:
                continue

            login_possible = bool(shell) and shell not in _INVALID_SHELLS

            user_nid = mkid("User", name)
            self.g.add_node(user_nid, "User", {
                "name":           name,
                "uid":            user.get("uid"),
                "gid":            user.get("gid"),
                "home":           user.get("home", ""),
                "shell":          shell,
                "login_possible": login_possible,
            }, prov(EXTRACTED, "users_groups.json", 0.95))

            if user.get("has_password") and user.get("password_hash"):
                hash_val = user["password_hash"]
                algo, strength, cwe_id = resolve_hash_algo(hash_val)

                cred_nid = mkid("Credential", "user_hash", name)
                self.g.add_node(cred_nid, "Credential", {
                    "type":           "password_hash",
                    "username":       name,
                    "hash_algorithm": algo,
                    "strength":       strength,
                    "cwe":            cwe_id or "",
                    "description":    f"Password hash for '{name}' using {algo}",
                }, prov(EXTRACTED, "users_groups.json", 0.95))
                self.g.add_edge(user_nid, cred_nid, "HAS_CREDENTIAL", {},
                                prov(EXTRACTED, "users_groups.json", 0.95))

                if cwe_id:  # weak hash algorithm
                    w_nid = mkid("Weakness", "weak_hash", name)
                    self.g.add_node(w_nid, "Weakness", {
                        "type":        "weak_password_hash",
                        "username":    name,
                        "algorithm":   algo,
                        "cwe":         cwe_id,
                        "description": (
                            f"Weak password hash ({algo}) for user '{name}' — "
                            "offline brute-force with Hashcat/John feasible"
                        ),
                        "severity":    "high",
                    }, prov(EXTRACTED, "users_groups.json", 0.95))
                    self.g.add_edge(cred_nid, w_nid, "EXPOSES_WEAKNESS", {},
                                    prov(EXTRACTED, "users_groups.json", 0.95))

            if login_possible:
                for svc_type, svc_nid in svc_nids.items():
                    if svc_type in _SHELL_AUTH_SERVICES:
                        self.g.add_edge(svc_nid, user_nid, "AUTHENTICATES_WITH", {},
                                        prov(INFERRED, "users_groups.json", 0.80))

    # ── Attack path derivation ────────────────────────────────────────────────

    def derive_attack_paths(self, zones: dict[str, str]) -> list[dict]:
        """
        Derive attack paths by traversing the graph from each TrustZone.

        For each non-LOCAL zone, finds ports reachable from that zone, walks backward
        through Service → Binary, collects process context, crypto, and weakness nodes,
        then scores severity from zone + privilege + weakness count.
        """
        paths = []
        g = self.g

        for zone_name, zone_nid in zones.items():
            if zone_name == "LOCAL":
                continue

            reachable_ports = [
                nid for nid, data in g.nodes.items()
                if data["type"] == "Port" and g.has_edge(nid, zone_nid)
            ]

            for port_nid in reachable_ports:
                port_attrs = g.nodes[port_nid]["attributes"]
                services   = g.predecessors(port_nid, "EXPOSES")

                for svc_nid in services:
                    svc_attrs = g.nodes[svc_nid]["attributes"]
                    binaries  = g.predecessors(svc_nid, "PROVIDES")

                    pc_nids       = g.successors(svc_nid, "RUNS_AS")
                    runs_as_root  = any(
                        g.nodes[n]["attributes"].get("uid") == 0
                        for n in pc_nids
                    )

                    crypto_algos: list[str] = []
                    for bin_nid in binaries:
                        for prim_nid in g.successors(bin_nid, "USES_CRYPTO"):
                            algo = g.nodes[prim_nid]["attributes"].get("algorithm", "")
                            if algo and algo not in crypto_algos:
                                crypto_algos.append(algo)

                    weakness_types: list[str] = []
                    weakness_score: float = 0.0

                    # Sources: binaries (direct) + their linked certificates
                    weakness_sources: list[str] = list(binaries)
                    for bin_nid in binaries:
                        weakness_sources.extend(g.successors(bin_nid, "LINKS_TO"))
                    # Global context: every FilesystemObject and Certificate node
                    # (world-writable, debug artifacts, shellcheck, TLS config, cert issues)
                    # are reachable by any attacker who gains a foothold on this service.
                    for nid, data in g.nodes.items():
                        if data["type"] in ("FilesystemObject", "Certificate"):
                            weakness_sources.append(nid)

                    for src_nid in weakness_sources:
                        for w_nid in g.successors(src_nid, "EXPOSES_WEAKNESS"):
                            wattrs = g.nodes[w_nid]["attributes"]
                            wt = wattrs.get("type", "")
                            if wt and wt not in weakness_types:
                                weakness_types.append(wt)
                                weakness_score += _SEV_WEIGHT.get(
                                    wattrs.get("severity", "low"), 0.5
                                )

                    # Walk service → users → credentials → weaknesses (targeted auth context)
                    weak_auth_users: list[str] = []
                    for user_nid in g.successors(svc_nid, "AUTHENTICATES_WITH"):
                        uattrs = g.nodes[user_nid]["attributes"]
                        for cred_nid in g.successors(user_nid, "HAS_CREDENTIAL"):
                            if g.nodes[cred_nid]["attributes"].get("strength") == "weak":
                                uname = uattrs.get("name", "?")
                                if uname not in weak_auth_users:
                                    weak_auth_users.append(uname)
                            for w_nid in g.successors(cred_nid, "EXPOSES_WEAKNESS"):
                                wattrs = g.nodes[w_nid]["attributes"]
                                wt = wattrs.get("type", "")
                                if wt and wt not in weakness_types:
                                    weakness_types.append(wt)
                                    weakness_score += _SEV_WEIGHT.get(
                                        wattrs.get("severity", "low"), 0.5
                                    )

                    # ── Targeted bonus 1: dangerous functions on service binary ──────
                    # Name-based lookup compensates for the path-format mismatch between
                    # entry_point binary nodes (absolute paths) and dangerous_functions
                    # binary nodes (relative paths), which would otherwise give them
                    # different mkids and miss the EXPOSES_WEAKNESS edges.
                    dangerous_func_score: float = 0.0
                    dangerous_funcs: list[str] = []
                    bin_names = (
                        {g.nodes[b]["attributes"].get("name", "") for b in binaries} - {""}
                    )
                    df_seen: set[str] = set()
                    for nid, data in g.nodes.items():
                        if (
                            data["type"] == "Binary"
                            and data["attributes"].get("name", "") in bin_names
                        ):
                            for w_nid in g.successors(nid, "EXPOSES_WEAKNESS"):
                                wattrs = g.nodes[w_nid]["attributes"]
                                wtype  = wattrs.get("type", "")
                                if wtype.startswith("dangerous_function_") and wtype not in df_seen:
                                    df_seen.add(wtype)
                                    dangerous_func_score += _SEV_WEIGHT.get(
                                        wattrs.get("severity", "low"), 0.5
                                    )
                                    fn = wattrs.get("function", wtype[len("dangerous_function_"):])
                                    if fn not in dangerous_funcs:
                                        dangerous_funcs.append(fn)

                    # ── Targeted bonus 2: cert/TLS issues on binary-linked certs ────
                    cert_issue_score: float = 0.0
                    cert_issues: list[str] = []
                    ci_seen: set[str] = set()
                    for bin_nid in binaries:
                        for cert_nid in g.successors(bin_nid, "LINKS_TO"):
                            for w_nid in g.successors(cert_nid, "EXPOSES_WEAKNESS"):
                                wattrs = g.nodes[w_nid]["attributes"]
                                wtype  = wattrs.get("type", "")
                                if wtype not in ci_seen:
                                    ci_seen.add(wtype)
                                    cert_issue_score += _SEV_WEIGHT.get(
                                        wattrs.get("severity", "low"), 0.5
                                    )
                                    issue = wattrs.get("flag", wtype.replace("certificate_", ""))
                                    if issue not in cert_issues:
                                        cert_issues.append(issue)

                    # ── Targeted bonus 3: hardcoded credential exposure ───────────
                    # Walks CONTAINS_SECRET edges from FilesystemObject and Firmware nodes.
                    # password_hash/shadow_hash excluded — already scored via the
                    # weak_auth_users → EXPOSES_WEAKNESS chain above.
                    cred_exposure_score: float = 0.0
                    exposed_cred_types: list[str] = []
                    ce_seen: set[str] = set()
                    for nid, data in g.nodes.items():
                        if data["type"] in ("FilesystemObject", "Firmware"):
                            for cred_nid in g.successors(nid, "CONTAINS_SECRET"):
                                if g.nodes[cred_nid]["type"] == "Credential":
                                    ctype = g.nodes[cred_nid]["attributes"].get("type", "")
                                    w = _CRED_EXPOSURE_WEIGHT.get(ctype, 0.0)
                                    if w and ctype not in ce_seen:
                                        ce_seen.add(ctype)
                                        cred_exposure_score += w
                                        exposed_cred_types.append(ctype)

                    score: float = 0.0
                    if zone_name == "WAN":   score += 3
                    elif zone_name == "LAN": score += 1
                    if runs_as_root:         score += 3
                    score += min(len(crypto_algos), 2)
                    score += min(weakness_score,       4)
                    score += min(dangerous_func_score, 2)
                    score += min(cert_issue_score,     2)
                    score += min(cred_exposure_score,  2)

                    if score >= 6:   severity = "critical"
                    elif score >= 4: severity = "high"
                    elif score >= 2: severity = "medium"
                    else:            severity = "low"

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
                        "runs_as_root":          runs_as_root,
                        "crypto_weaknesses":      crypto_algos,
                        "structural_weaknesses":  weakness_types,
                        "weak_auth_users":        weak_auth_users,
                        "dangerous_funcs":        dangerous_funcs,
                        "cert_issues":            cert_issues,
                        "exposed_cred_types":     exposed_cred_types,
                        "dangerous_func_score":   round(dangerous_func_score, 2),
                        "cert_issue_score":       round(cert_issue_score, 2),
                        "cred_exposure_score":    round(cred_exposure_score, 2),
                        "steps": _derive_steps(
                            zone_name, port_attrs, svc_attrs,
                            runs_as_root, crypto_algos, weak_auth_users,
                            dangerous_funcs, cert_issues, exposed_cred_types,
                        ),
                        "provenance": prov(INFERRED, "graph_traversal", 0.80),
                    })

        _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(paths, key=lambda p: (_SEV_ORDER[p["severity"]], -p["score"]))


# ── Top-level build ───────────────────────────────────────────────────────────

def build(surface: dict, firmware_id: str) -> tuple[Graph, list[dict]]:
    builder = GraphBuilder(firmware_id)

    builder._build_firmware(surface)
    zones = builder._build_trust_zones()
    # _build_protocols runs first so protocol Service/Port nodes are created with
    # evidence attributes; _build_network_layer then adds Binary+PROVIDES edges
    # for any protocol also present in entry_points (add_node is idempotent).
    proto_svc_nids = builder._build_protocols(surface, zones)
    _, ep_svc_nids = builder._build_network_layer(surface, zones)
    svc_nids = {**proto_svc_nids, **ep_svc_nids}
    builder._build_process_contexts(surface, svc_nids)
    builder._build_users(surface, svc_nids)
    builder._build_crypto(surface)
    builder._build_fs_and_weaknesses(surface)
    builder._build_credentials(surface)
    builder._build_certificates(surface)
    builder._build_certificate_issues(surface)
    builder._build_shellcheck(surface)
    builder._build_hardening(surface)
    builder._build_dangerous_functions(surface)
    builder._build_tls_config_issues(surface)
    builder._build_ipc(surface)

    attack_paths = builder.derive_attack_paths(zones)
    return builder.g, attack_paths
