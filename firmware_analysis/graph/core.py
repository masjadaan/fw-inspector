"""Graph schema, constants, helper functions, and the Graph data structure."""

import uuid
from collections import defaultdict, deque


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
