#!/usr/bin/env python3
"""
Full firmware analysis pipeline — single command.

Runs all stages in order:
  1. extract.py   — Docker build + carve + analyze (produces raw/ and sbom/)
  2. surface.py   — attack surface model           (produces attack_surface/)
  3. graph.py     — entity-relationship graph       (produces graph.json + graph.dot)
  4. dot          — render graph to SVG             (requires graphviz, optional)
  5. cve.py       — CVE enrichment via grype        (produces cve_report.json)
  6. heatmap.py   — severity heatmap                (produces cve_heatmap.png)

Each stage records success | partial | failed | skipped in pipeline_manifest.json.
Downstream stages are auto-skipped when their dependency fails.

Usage:
    python3 pipeline.py input/TP-Link/Archer_A5_v6.20/Archer_A5V6.bin
    python3 pipeline.py firmware.bin --output ./results --skip-build
"""

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

Status = Literal["success", "partial", "failed", "skipped"]

_STATUS_ICON = {"success": "OK ", "partial": "~  ", "failed": "!!!", "skipped": "---"}


@dataclass
class StageResult:
    name:       str
    status:     Status        = "skipped"
    exit_code:  int | None    = None
    duration_s: float         = 0.0
    notes:      list[str]     = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status":     self.status,
            "exit_code":  self.exit_code,
            "duration_s": round(self.duration_s, 1),
            "notes":      self.notes,
        }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _banner(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def _run_stage(
    key: str,
    label: str,
    cmd: list[str],
    stages: dict[str, StageResult],
    *,
    required: bool = True,
    blocked_by: str | None = None,
) -> StageResult:
    """Run one pipeline stage. Skips automatically if its dependency failed/skipped."""
    result = StageResult(name=label)

    if blocked_by:
        dep = stages.get(blocked_by)
        if dep and dep.status in ("failed", "skipped"):
            result.status = "skipped"
            result.notes.append(f"dependency '{blocked_by}' {dep.status}")
            stages[key] = result
            _banner(label)
            print(f"[−] Skipped — {result.notes[0]}.")
            return result

    _banner(label)
    print(f"[>] {' '.join(str(c) for c in cmd)}\n")

    t0 = time.monotonic()
    proc = subprocess.run(cmd)
    result.duration_s = time.monotonic() - t0
    result.exit_code  = proc.returncode

    if proc.returncode == 0:
        result.status = "success"
    elif required:
        result.status = "failed"
        print(f"\n[!] {label} failed (exit {proc.returncode}).")
    else:
        result.status = "partial"
        print(f"\n[~] {label} incomplete (exit {proc.returncode}).")

    stages[key] = result
    return result


def _write_manifest(
    analysis_dir: Path,
    firmware_id: str,
    run_at: str,
    stages: dict[str, StageResult],
) -> None:
    manifest = {
        "firmware_id": firmware_id,
        "run_at":      run_at,
        "stages":      {k: v.to_dict() for k, v in stages.items()},
    }
    (analysis_dir / "pipeline_manifest.json").write_text(json.dumps(manifest, indent=2))


def _print_summary(analysis_dir: Path, stages: dict[str, StageResult]) -> None:
    _banner("Pipeline summary")
    for key, r in stages.items():
        icon = _STATUS_ICON.get(r.status, "   ")
        note = f"  ({r.notes[0]})" if r.notes else ""
        dur  = f"  {r.duration_s:.1f}s" if r.duration_s else ""
        print(f"  [{icon}] {r.name}{dur}{note}")

    print(f"\n  Manifest : {analysis_dir}/pipeline_manifest.json")
    print(f"  Output   : {analysis_dir}/")
    print(f"    raw/                   ← analysis findings")
    print(f"    sbom/                  ← sbom.cdx.json · cve_report.json · cve_heatmap.png")
    print(f"    attack_surface/        ← attack_surface.json · graph.json · graph.dot · graph.svg")


# ── Main ───────────────────────────────────────────────────────────────────────

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

    firmware     = args.firmware.resolve()
    output_dir   = args.output.resolve()
    firmware_id  = firmware.stem
    analysis_dir = output_dir / firmware_id

    if not firmware.exists():
        print(f"[!] File not found: {firmware}")
        sys.exit(1)

    analysis_dir.mkdir(parents=True, exist_ok=True)

    py      = sys.executable
    here    = Path(__file__).parent
    run_at  = datetime.now(timezone.utc).isoformat()
    stages: dict[str, StageResult] = {}

    def flush() -> None:
        _write_manifest(analysis_dir, firmware_id, run_at, stages)

    # ── Stage 1: Extract + Analyse ────────────────────────────────────────────
    extract_cmd = [
        py, str(here / "firmware_analysis/extraction/extract.py"),
        str(firmware), "--output", str(output_dir),
    ]
    if args.skip_build:
        extract_cmd.append("--skip-build")
    _run_stage("1_extract", "Stage 1 — Extract & Analyse", extract_cmd, stages)
    flush()

    # ── Stage 2: Attack Surface ───────────────────────────────────────────────
    _run_stage(
        "2_surface", "Stage 2 — Attack Surface",
        [py, str(here / "firmware_analysis/surface/surface.py"), str(analysis_dir)],
        stages, blocked_by="1_extract",
    )
    flush()

    # ── Stage 3: Entity-Relationship Graph ────────────────────────────────────
    attack_surface_json = analysis_dir / "attack_surface" / "attack_surface.json"
    _run_stage(
        "3_graph", "Stage 3 — Entity-Relationship Graph",
        [py, str(here / "firmware_analysis/graph/graph.py"), str(attack_surface_json), "--dot", "--focused-graphs"],
        stages, blocked_by="2_surface",
    )
    flush()

    # ── Stage 4: Render graphs to SVG (optional — graphviz may not be installed) ─
    as_dir   = analysis_dir / "attack_surface"
    dot_file = as_dir / "graph.dot"
    svg_file = as_dir / "graph.svg"
    r4 = _run_stage(
        "4_svg", "Stage 4 — Render Graph SVG",
        ["dot", "-Tsvg", str(dot_file), "-o", str(svg_file)],
        stages, required=False, blocked_by="3_graph",
    )
    if r4.status == "partial":
        stages["4_svg"].notes.append("install graphviz: sudo apt install graphviz")

    _focused_keys = [
        "entry_points", "stack_hardening", "memory_unsafe",
        "command_injection", "weak_randomness_misc",
    ]
    for focus_key in _focused_keys:
        focused_dot = as_dir / f"graph_{focus_key}.dot"
        focused_svg = as_dir / f"graph_{focus_key}.svg"
        _run_stage(
            f"4_svg_{focus_key}", f"Stage 4 — Render {focus_key} SVG",
            ["dot", "-Tsvg", str(focused_dot), "-o", str(focused_svg)],
            stages, required=False, blocked_by="3_graph",
        )
    flush()

    # ── Stage 5: CVE Enrichment ───────────────────────────────────────────────
    if args.skip_cve:
        stages["5_cve"] = StageResult(
            name="Stage 5 — CVE Enrichment", status="skipped", notes=["--skip-cve"]
        )
        _banner("Stage 5 — CVE Enrichment")
        print("[−] Skipped (--skip-cve).")
    else:
        # Blocked by 3_graph: prevents running CVE enrichment with a stale graph.json
        # from a previous run when the current graph build failed.
        _run_stage(
            "5_cve", "Stage 5 — CVE Enrichment",
            [py, str(here / "firmware_analysis/cve/cve.py"), str(analysis_dir)],
            stages, blocked_by="3_graph",
        )
    flush()

    # ── Stage 6: Heatmap ──────────────────────────────────────────────────────
    _run_stage(
        "6_heatmap", "Stage 6 — CVE Severity Heatmap",
        [py, str(here / "firmware_analysis/reporting/heatmap.py"), str(analysis_dir)],
        stages, blocked_by="5_cve",
    )
    flush()

    # ── Summary ───────────────────────────────────────────────────────────────
    _print_summary(analysis_dir, stages)

    if any(r.status == "failed" for r in stages.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
