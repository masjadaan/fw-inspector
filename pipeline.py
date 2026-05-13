#!/usr/bin/env python3
"""
Full firmware analysis pipeline — single command.

Runs all stages in order:
  1. extract.py   — Docker build + carve + analyze (produces raw/ and sbom/)
  2. surface.py   — attack surface model           (produces attack_surface/)
  3. graph.py     — entity-relationship graph       (produces graph.json + graph.dot)
  4. dot          — render graph to SVG             (requires graphviz)
  5. cve.py       — CVE enrichment via grype        (produces cve_report.json)
  6. heatmap.py   — severity heatmap                (produces cve_heatmap.png)

Usage:
    python3 pipeline.py input/TP-Link/Archer_A5_v6.20/Archer_A5V6.bin
    python3 pipeline.py firmware.bin --output ./results --skip-build
"""

import argparse
import subprocess
import sys
from pathlib import Path


def _banner(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def _run(label: str, cmd: list[str], *, check: bool = True) -> bool:
    """Run a command, stream output live, return True on success."""
    _banner(label)
    print(f"[>] {' '.join(str(c) for c in cmd)}\n")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"\n[!] {label} failed (exit {result.returncode}).")
        if check:
            sys.exit(result.returncode)
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the full firmware analysis pipeline in one command."
    )
    parser.add_argument(
        "firmware", type=Path,
        help="Path to firmware binary.",
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=Path("./analysis"),
        help="Host directory for all output (default: ./analysis).",
    )
    parser.add_argument(
        "--skip-build", action="store_true",
        help="Skip Docker image rebuild.",
    )
    parser.add_argument(
        "--skip-cve", action="store_true",
        help="Skip CVE enrichment (grype not required).",
    )
    args = parser.parse_args()

    firmware   = args.firmware.resolve()
    output_dir = args.output.resolve()
    firmware_id = firmware.stem
    analysis_dir = output_dir / firmware_id

    if not firmware.exists():
        print(f"[!] File not found: {firmware}")
        sys.exit(1)

    py = sys.executable   # same interpreter that launched pipeline.py
    here = Path(__file__).parent

    # ── Stage 1: Extract + Analyse ────────────────────────────────────────────
    extract_cmd = [py, str(here / "extract.py"), str(firmware), "--output", str(output_dir)]
    if args.skip_build:
        extract_cmd.append("--skip-build")
    _run("Stage 1 — Extract & Analyse", extract_cmd)

    # ── Stage 2: Attack Surface ───────────────────────────────────────────────
    _run("Stage 2 — Attack Surface", [
        py, str(here / "surface.py"), str(analysis_dir),
    ])

    # ── Stage 3: Entity-Relationship Graph ────────────────────────────────────
    attack_surface_json = analysis_dir / "attack_surface" / "attack_surface.json"
    _run("Stage 3 — Entity-Relationship Graph", [
        py, str(here / "graph.py"), str(attack_surface_json), "--dot",
    ])

    # ── Stage 4: Render graph to SVG ─────────────────────────────────────────
    dot_file = analysis_dir / "attack_surface" / "graph.dot"
    svg_file = analysis_dir / "attack_surface" / "graph.svg"
    ok = _run("Stage 4 — Render Graph SVG", [
        "dot", "-Tsvg", str(dot_file), "-o", str(svg_file),
    ], check=False)
    if not ok:
        print("    (install graphviz to enable SVG rendering: sudo apt install graphviz)")

    # ── Stage 5: CVE Enrichment ───────────────────────────────────────────────
    if args.skip_cve:
        _banner("Stage 5 — CVE Enrichment")
        print("[*] Skipped (--skip-cve).")
    else:
        _run("Stage 5 — CVE Enrichment", [
            py, str(here / "cve.py"), str(analysis_dir),
        ])

        # ── Stage 6: Heatmap ──────────────────────────────────────────────────
        _run("Stage 6 — CVE Severity Heatmap", [
            py, str(here / "heatmap.py"), str(analysis_dir),
        ])

    # ── Summary ───────────────────────────────────────────────────────────────
    _banner("Pipeline complete")
    print(f"  Output : {analysis_dir}/")
    print(f"    raw/                   ← analysis findings")
    print(f"    sbom/                  ← sbom.cdx.json · cve_report.json · cve_heatmap.png")
    print(f"    attack_surface/        ← attack_surface.json · graph.json · graph.dot · graph.svg")


if __name__ == "__main__":
    main()
