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
from pathlib import Path

from builder import build
from export import FOCUS_CONFIGS, to_dict, to_dot, to_focused_dot


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
    parser.add_argument(
        "--focused-graphs",
        action="store_true",
        help="Write 5 focused DOT files (entry_points, stack_hardening, etc.)",
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

    if args.focused_graphs:
        print()
        for focus_key, cfg in FOCUS_CONFIGS.items():
            focused_dot  = to_focused_dot(g, firmware_id, focus_key)
            focused_path = out_path.with_name(f"graph_{focus_key}.dot")
            focused_path.write_text(focused_dot)
            print(f"[+] Focused DOT ({cfg['title']}) → {focused_path}")


if __name__ == "__main__":
    main()
