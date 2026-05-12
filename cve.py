#!/usr/bin/env python3
"""
CVE enrichment — Option B (host-side).

Runs Grype against the SBOM produced by analyze.py, then cross-references
every CVE finding with two firmware-specific signals already in the SBOM:

  1. Hardening flags (NX / PIE / RELRO / stack canary) stored as CycloneDX
     properties on each component — a vulnerable library in a binary with no
     mitigations is far more exploitable than the same library in a hardened one.

  2. Network reachability — derived by tracing entry-point binaries (from
     <firmware>_attack_surface.json) through their NEEDED shared libraries.
     A CVE in a library linked by httpd or dropbear is immediately reachable
     from the network; one only linked by an offline utility is not.

Output: <analysis_dir>/cve_report.json
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


# ── Severity ladder ────────────────────────────────────────────────────────────

_LEVELS  = ["none", "info", "low", "medium", "high", "critical"]
_WEIGHT  = {s: i for i, s in enumerate(_LEVELS)}


def _escalate(base: str, hardening: dict | None, reachable: bool) -> tuple[str, list[str]]:
    """Return (adjusted_severity, [reasons]) after applying firmware context."""
    weight  = _WEIGHT.get(base.lower(), 1)
    reasons: list[str] = []

    if reachable:
        weight += 2
        reasons.append("network-reachable entry point")

    if hardening:
        if hardening.get("nx") == "False":
            weight += 1
            reasons.append("NX disabled")
        if hardening.get("pie") == "no":
            weight += 1
            reasons.append("no PIE")
        if hardening.get("relro") == "none":
            weight += 1
            reasons.append("no RELRO")
        if hardening.get("canary") == "False":
            weight += 1
            reasons.append("no stack canary")

    return _LEVELS[min(weight, len(_LEVELS) - 1)], reasons


# ── SBOM parsing ───────────────────────────────────────────────────────────────

def _parse_sbom(sbom: dict) -> tuple[dict, dict]:
    """Return (ref_to_meta, name_to_ref) from a CycloneDX SBOM.

    ref_to_meta maps bom-ref → {name, type, version, hardening, needed_libs}.
    name_to_ref maps canonical component name → bom-ref.
    """
    ref_to_meta: dict = {}
    name_to_ref: dict = {}

    for comp in sbom.get("components", []):
        ref  = comp.get("bom-ref", "")
        name = comp.get("name", "")
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}

        needed_raw = props.get("firmware:needed_libs", "")
        needed_libs = [
            re.sub(r'\.so.*$', '', lib.strip())
            for lib in needed_raw.split(",")
            if lib.strip()
        ]

        meta = {
            "name":    name,
            "type":    comp.get("type", ""),
            "version": comp.get("version", ""),
            "hardening": {
                "nx":     props.get("firmware:nx"),
                "pie":    props.get("firmware:pie"),
                "relro":  props.get("firmware:relro"),
                "canary": props.get("firmware:canary"),
            },
            "needed_libs": needed_libs,
        }
        ref_to_meta[ref]  = meta
        name_to_ref[name] = ref

    return ref_to_meta, name_to_ref


# ── Reachability ───────────────────────────────────────────────────────────────

def _reachable_libs(attack_surface: Path | None, ref_to_meta: dict, name_to_ref: dict) -> set[str]:
    """Return the set of canonical library names reachable from network entry points.

    Traces: entry_point.binary → SBOM component → firmware:needed_libs.
    Returns canonical names (libssl, libcrypto, …) matched against SBOM component names.
    """
    if not attack_surface or not attack_surface.exists():
        return set()

    data = json.loads(attack_surface.read_text())
    entry_binaries: list[str] = []
    for ep in data.get("entry_points", []):
        raw = ep.get("binary", "")
        entry_binaries.append(Path(raw).name)   # "/output/.../httpd" → "httpd"

    reachable: set[str] = set()
    for bin_name in entry_binaries:
        ref = name_to_ref.get(bin_name)
        if not ref:
            continue
        meta = ref_to_meta[ref]
        for lib_canon in meta["needed_libs"]:
            reachable.add(lib_canon)
        # also mark the entry binary itself as reachable
        reachable.add(bin_name)

    return reachable


# ── Grype ──────────────────────────────────────────────────────────────────────

_GRYPE_FALLBACKS = [
    "grype",
    "./bin/grype",
    str(Path(__file__).parent / "bin" / "grype"),
]


def _find_grype() -> str:
    """Return the first usable grype executable, or exit with install instructions."""
    for candidate in _GRYPE_FALLBACKS:
        if subprocess.run(["which", candidate], capture_output=True).returncode == 0:
            return candidate
        if Path(candidate).is_file():
            return candidate
    print("[!] grype not found. Tried:", ", ".join(_GRYPE_FALLBACKS))
    print("    Install: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh")
    sys.exit(1)


def _run_grype(sbom_path: Path) -> list[dict]:
    """Run grype and return the vulnerabilities list from CycloneDX output."""
    grype = _find_grype()
    print(f"[*] Running grype ({grype}) against {sbom_path.name} ...")
    r = subprocess.run(
        [grype, f"sbom:{sbom_path}", "--output", "cyclonedx-json", "--quiet"],
        capture_output=True, text=True,
    )
    if not r.stdout.strip():
        print(f"[!] grype produced no output.\n    stderr: {r.stderr.strip()}")
        sys.exit(1)
    try:
        return json.loads(r.stdout).get("vulnerabilities", [])
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse grype output: {e}")
        sys.exit(1)


# ── Report building ────────────────────────────────────────────────────────────

def _build_report(
    vulnerabilities: list[dict],
    ref_to_meta: dict,
    reachable: set[str],
    firmware_id: str,
    sbom_path: Path,
) -> dict:
    findings: list[dict] = []

    for vuln in vulnerabilities:
        cve_id  = vuln.get("id", "")
        ratings = vuln.get("ratings", [])
        base_sev = ratings[0].get("severity", "unknown").lower() if ratings else "unknown"
        cvss     = ratings[0].get("score")                       if ratings else None

        for affect in vuln.get("affects", []):
            ref  = affect.get("ref", "")
            meta = ref_to_meta.get(ref, {})
            name = meta.get("name", ref)

            is_reachable = name in reachable
            h = meta.get("hardening")
            adj_sev, reasons = _escalate(base_sev, h, is_reachable)

            findings.append({
                "cve":               cve_id,
                "component":         name,
                "version":           meta.get("version", ""),
                "base_severity":     base_sev,
                "adjusted_severity": adj_sev,
                "cvss_score":        cvss,
                "escalated":         adj_sev != base_sev,
                "escalation_reasons": reasons,
                "network_reachable": is_reachable,
                "hardening": {
                    k: v for k, v in (h or {}).items() if v is not None
                },
                "description":    vuln.get("description", ""),
                "recommendation": vuln.get("recommendation", ""),
            })

    findings.sort(
        key=lambda f: (_WEIGHT.get(f["adjusted_severity"], 0), f["cvss_score"] or 0),
        reverse=True,
    )

    by_adj: dict = {s: 0 for s in _LEVELS}
    for f in findings:
        by_adj[f["adjusted_severity"]] = by_adj.get(f["adjusted_severity"], 0) + 1

    escalated_count = sum(1 for f in findings if f["escalated"])

    return {
        "firmware":              firmware_id,
        "sbom":                  str(sbom_path),
        "total_vulnerabilities": len(findings),
        "escalated":             escalated_count,
        "by_adjusted_severity":  by_adj,
        "vulnerabilities":       findings,
    }


# ── Summary printer ────────────────────────────────────────────────────────────

def _print_summary(report: dict, out_path: Path) -> None:
    total = report["total_vulnerabilities"]
    print(f"\n[+] CVE enrichment complete — {total} finding(s)\n")

    sev_map = report["by_adjusted_severity"]
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = sev_map.get(sev, 0)
        if n:
            bar = "!" * min(n, 40)
            print(f"    {sev.upper():8s}  {n:3d}  {bar}")

    esc = report["escalated"]
    if esc:
        print(f"\n    {esc} finding(s) escalated due to firmware context (hardening / reachability)")

    print(f"\n    Report : {out_path}")

    print("\n[*] Top 10 findings:")
    for f in report["vulnerabilities"][:10]:
        esc_tag = " [ESCALATED]" if f["escalated"] else ""
        reach   = " [REACHABLE]" if f["network_reachable"] else ""
        reasons = f"  ← {', '.join(f['escalation_reasons'])}" if f["escalation_reasons"] else ""
        print(f"    {f['adjusted_severity'].upper():8s}  {f['cve']:20s}  {f['component']}{esc_tag}{reach}{reasons}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich firmware SBOM with CVE data (Grype) and firmware-aware severity."
    )
    parser.add_argument(
        "analysis_dir", type=Path,
        help="Analysis directory produced by analyze.py (must contain sbom.cdx.json).",
    )
    parser.add_argument(
        "--attack-surface", "-a", type=Path, default=None,
        help="<firmware>_attack_surface.json for network-reachability cross-referencing. "
             "Auto-detected from the parent of analysis_dir if omitted.",
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output path for CVE report JSON (default: <analysis_dir>/cve_report.json).",
    )
    args = parser.parse_args()

    analysis_dir = args.analysis_dir.resolve()
    sbom_path    = analysis_dir / "sbom.cdx.json"
    firmware_id  = analysis_dir.name

    if not sbom_path.exists():
        print(f"[!] {sbom_path} not found.")
        print(f"    Run the analysis pipeline first: python3 extract.py <firmware>")
        sys.exit(1)

    # Auto-detect attack surface JSON if not provided
    attack_surface = args.attack_surface
    if not attack_surface:
        candidate = analysis_dir.parent / f"{firmware_id}_attack_surface.json"
        if candidate.exists():
            attack_surface = candidate
            print(f"[*] Auto-detected attack surface: {candidate.name}")

    sbom         = json.loads(sbom_path.read_text())
    ref_to_meta, name_to_ref = _parse_sbom(sbom)

    reachable = _reachable_libs(attack_surface, ref_to_meta, name_to_ref)
    if reachable:
        print(f"[*] Network-reachable libraries: {', '.join(sorted(reachable))}")
    else:
        print("[*] No attack surface loaded — reachability escalation disabled.")

    vulnerabilities = _run_grype(sbom_path)

    out_path = args.output or analysis_dir / "cve_report.json"
    report   = _build_report(vulnerabilities, ref_to_meta, reachable, firmware_id, sbom_path)
    out_path.write_text(json.dumps(report, indent=2))

    _print_summary(report, out_path)


if __name__ == "__main__":
    main()
