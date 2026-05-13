#!/usr/bin/env python3
"""
Synthesizes a structured attack surface model from analyze.py output files.
Reads from an analysis directory produced by analyze.py and writes attack_surface.json.

Usage:
    python3 surface.py ./analysis/Archer_A5V6/
    python3 surface.py ./analysis/Archer_A5V6/ --output ./report/
"""

import argparse
import json
from pathlib import Path

from parsers import (
    parse_architecture,
    parse_capabilities,
    parse_certs,
    parse_credentials,
    parse_debug,
    parse_hardening,
    parse_init_services,
    parse_ipc,
    parse_nvram,
    parse_protocols,
    parse_setuid,
    parse_shellcheck,
    parse_users,
    parse_weak_crypto,
    parse_web,
    parse_world_writable,
)
from attack_paths import build_entry_points, infer_attack_paths


def build_model(analysis_dir: Path, firmware_id: str, raw_dir: Path | None = None) -> dict:
    raw_dir = raw_dir or analysis_dir
    print(f"[*] Parsing analysis files from {raw_dir}/")

    users          = parse_users(raw_dir)
    setuid         = parse_setuid(raw_dir)
    caps           = parse_capabilities(raw_dir)
    world_writable = parse_world_writable(raw_dir)
    init           = parse_init_services(raw_dir)
    web            = parse_web(raw_dir)
    protocols      = parse_protocols(raw_dir)
    credentials    = parse_credentials(raw_dir)
    weak_crypto    = parse_weak_crypto(raw_dir)
    debug          = parse_debug(raw_dir)
    ipc            = parse_ipc(raw_dir)
    certs          = parse_certs(raw_dir)
    nvram          = parse_nvram(raw_dir)
    shellcheck     = parse_shellcheck(raw_dir)
    hardening      = parse_hardening(raw_dir)
    arch           = parse_architecture(raw_dir)

    privesc = {
        "setuid_binaries": setuid,
        "capabilities":    caps,
        "world_writable":  world_writable,
    }

    entry_points = build_entry_points(init, web, protocols)
    attack_paths = infer_attack_paths(
        entry_points, init, web, users, credentials,
        privesc, protocols, weak_crypto, debug, certs,
    )

    return {
        "firmware": {
            "id":               firmware_id,
            "analysis_dir":     str(analysis_dir),
            "arch":             arch["arch"],
            "bits":             arch["bits"],
            "endianness":       arch["endianness"],
            "endianness_short": arch["endianness_short"],
            "arch_confidence":  arch["confidence"],
            "arch_elf_count":   arch["elf_count"],
        },
        "summary": {
            "entry_points_count":    len(entry_points),
            "attack_paths_count":    len(attack_paths),
            "critical_paths":        sum(1 for p in attack_paths if p["severity"] == "critical"),
            "high_paths":            sum(1 for p in attack_paths if p["severity"] == "high"),
            "users_with_password":   sum(1 for u in users if u["has_password"]),
            "setuid_binaries_count": len(setuid),
            "world_writable_count":  len(world_writable["files"]) + len(world_writable["dirs"]),
        },
        "entry_points":      entry_points,
        "users":             users,
        "privilege_escalation": privesc,
        "credentials":       credentials,
        "protocols":         protocols,
        "weak_crypto":       weak_crypto,
        "debug_artifacts":   debug,
        "ipc":               ipc,
        "certificates":      certs,
        "nvram_references":  nvram,
        "shellcheck":        shellcheck,
        "hardening":         hardening,
        "web":               web,
        "attack_paths":      attack_paths,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Build a structured attack surface model from analyze.py output."
    )
    parser.add_argument(
        "analysis_dir",
        type=Path,
        help="Directory produced by analyze.py (e.g. ./analysis/Archer_A5V6/).",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output JSON file (default: <analysis_dir>/attack_surface/attack_surface.json).",
    )
    args = parser.parse_args()

    analysis_dir = args.analysis_dir.resolve()
    if not analysis_dir.is_dir():
        print(f"[!] Not a directory: {analysis_dir}")
        raise SystemExit(1)

    firmware_id = analysis_dir.name
    if args.output:
        out_file = args.output
    else:
        as_dir = analysis_dir / "attack_surface"
        as_dir.mkdir(exist_ok=True)
        out_file = as_dir / "attack_surface.json"

    model = build_model(analysis_dir, firmware_id, raw_dir=analysis_dir / "raw")

    out_file.write_text(json.dumps(model, indent=2))
    print(f"\n[+] Attack surface model written to {out_file}")

    summary = model["summary"]
    print(f"\n    Entry points  : {summary['entry_points_count']}")
    print(f"    Attack paths  : {summary['attack_paths_count']}  "
          f"({summary['critical_paths']} critical, {summary['high_paths']} high)")
    print(f"    Users w/ creds: {summary['users_with_password']}")
    print(f"    SetUID bins   : {summary['setuid_binaries_count']}")
    print(f"    World-writable: {summary['world_writable_count']}")


if __name__ == "__main__":
    main()
