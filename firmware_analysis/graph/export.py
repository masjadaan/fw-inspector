"""Serialise the entity-relationship graph to JSON and Graphviz DOT."""

from datetime import datetime, timezone
from pathlib import Path

from core import Graph, SCHEMA_VERSION


# ── JSON serialisation ────────────────────────────────────────────────────────

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
            "firmware_id":        firmware_id,
            "schema_version":     SCHEMA_VERSION,
            "generated_at":       datetime.now(timezone.utc).isoformat(),
            "node_count":         len(g.nodes),
            "edge_count":         len(g.edges),
            "node_type_counts":   type_counts,
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
        uid   = attrs.get("uid", "?")
        uname = attrs.get("username", "")
        caps  = attrs.get("capabilities", "")
        return f"uid={uid} ({uname})\ncaps={caps}"

    if t == "CryptoPrimitive":
        return f"{attrs.get('algorithm', '?')}\n{attrs.get('cwe', '')}"

    if t == "WeaknessClass":
        return f"{attrs.get('cwe', '?')}\n{trunc(attrs.get('description', ''), 30)}"

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
            uname    = attrs.get("username", "?")
            algo     = attrs.get("hash_algorithm", "")
            strength = attrs.get("strength", "")
            return f"{uname} ({algo})\n{strength} {cwe}"
        evidence = attrs.get("evidence", "")
        filepath = evidence.split(":")[0] if evidence else ""
        return f"{trunc(ctype, 28)}\n{trunc(filepath, 32)}\n{cwe}"

    if t == "Certificate":
        return f"{trunc(attrs.get('path', '?'), 32)}\n{attrs.get('type', '')}"

    return attrs.get("name") or attrs.get("algorithm") or attrs.get("username") or t


FOCUS_CONFIGS: dict[str, dict] = {
    "entry_points": {
        "title": "Entry Points",
        "node_types": {"Firmware", "TrustZone", "Service", "Port", "Credential"},
        "weakness_types": None,
    },
    "stack_hardening": {
        "title": "Stack Hardening Gaps",
        "node_types": None,
        "weakness_types": {"canary_no", "nx_disabled", "relro_none", "pie_no"},
    },
    "memory_unsafe": {
        "title": "Memory-Unsafe Functions",
        "node_types": None,
        "weakness_types": {
            "dangerous_function_strcpy", "dangerous_function_sprintf",
            "dangerous_function_sscanf", "dangerous_function_strcat",
            "dangerous_function_vsprintf",
        },
    },
    "command_injection": {
        "title": "Command Injection Risk",
        "node_types": None,
        "weakness_types": {"dangerous_function_system", "dangerous_function_popen"},
    },
    "weak_randomness_misc": {
        "title": "Weak Randomness & Miscellaneous",
        "node_types": None,
        "weakness_types": {
            "dangerous_function_srand", "dangerous_function_rand",
            "debug_artifact", "certificate_self_signed",
        },
    },
}


def to_focused_dot(g: Graph, firmware_id: str, focus_key: str) -> str:
    cfg   = FOCUS_CONFIGS[focus_key]
    title = cfg["title"]

    included: set[str] = set()

    if cfg["node_types"]:
        allowed = cfg["node_types"]
        included = {nid for nid, d in g.nodes.items() if d["type"] in allowed}
    else:
        wtypes = cfg["weakness_types"]

        weakness_ids = {
            nid for nid, d in g.nodes.items()
            if d["type"] == "Weakness" and d["attributes"].get("type") in wtypes
        }
        included.update(weakness_ids)

        # sources of EXPOSES_WEAKNESS edges (Binary or FilesystemObject)
        parent_ids: set[str] = set()
        for e in g.edges:
            if e["target"] in weakness_ids:
                parent_ids.add(e["source"])
        included.update(parent_ids)

        # one hop upstream from Binary parents: Service → Port → TrustZone
        service_ids: set[str] = set()
        for e in g.edges:
            if e["source"] in parent_ids and g.nodes[e["target"]]["type"] == "Service":
                service_ids.add(e["target"])
        included.update(service_ids)

        port_ids: set[str] = set()
        for e in g.edges:
            if e["source"] in service_ids and g.nodes[e["target"]]["type"] == "Port":
                port_ids.add(e["target"])
        included.update(port_ids)

        for e in g.edges:
            if e["source"] in port_ids and g.nodes[e["target"]]["type"] == "TrustZone":
                included.add(e["target"])

    included_edges = [
        e for e in g.edges
        if e["source"] in included and e["target"] in included
    ]

    lines = [
        "digraph AttackSurface {",
        f'  label="{firmware_id} — {title}";',
        '  graph [rankdir=LR fontname="Helvetica" bgcolor="#1a1a2e" '
        'labelfontcolor=white fontcolor=white];',
        '  node [style=filled fontname="Helvetica" fontsize=10 fontcolor=white shape=box];',
        '  edge [fontname="Helvetica" fontsize=8 fontcolor="#aaaaaa" color="#666666"];',
        "",
    ]

    for nid in included:
        data  = g.nodes[nid]
        t     = data["type"]
        attrs = data["attributes"]
        label = _dot_label(t, attrs).replace('"', "'")
        conf  = data["provenance"]["confidence"]
        ptype = data["provenance"]["type"][0].upper()
        color = _NODE_COLORS.get(t, "#555555")
        lines.append(
            f'  "{nid}" [label="{t}\\n{label}\\n[{ptype}:{conf}]" '
            f'fillcolor="{color}"];'
        )

    lines.append("")
    for e in included_edges:
        rel   = e["relationship"]
        style = _EDGE_STYLES.get(rel, "solid")
        conf  = e["provenance"]["confidence"]
        lines.append(
            f'  "{e["source"]}" -> "{e["target"]}" '
            f'[label="{rel}\\n[{conf}]" style={style}];'
        )

    lines.append("}")
    return "\n".join(lines)


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
        ptype = data["provenance"]["type"][0].upper()
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
