#!/usr/bin/env python3
"""
Generate a CVE severity heatmap from cve_report.json.

Rows    — components (sorted by weighted severity score, worst first)
Columns — adjusted severity levels: critical · high · medium · low · info
Cells   — count of CVEs at that severity for that component

Output: <analysis_dir>/cve_heatmap.png  (or --output path)

Usage:
    python3 heatmap.py analysis/Archer_A5V6/
    python3 heatmap.py analysis/Archer_A5V6/ --top 30 --output heatmap.png
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    import numpy as np
except ImportError:
    print("[!] matplotlib and numpy are required:  pip install matplotlib numpy")
    sys.exit(1)


_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_WEIGHTS    = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# One colour scale per severity column so intensity encodes count within column.
_COL_CMAPS = {
    "critical": "Reds",
    "high":     "Oranges",
    "medium":   "YlOrBr",
    "low":      "Blues",
    "info":     "Greens",
}


def _load_report(analysis_dir: Path) -> dict:
    path = analysis_dir / "sbom" / "cve_report.json"
    if not path.exists():
        print(f"[!] {path} not found.  Run cve.py first.")
        sys.exit(1)
    return json.loads(path.read_text())


def _build_matrix(vulnerabilities: list[dict], top: int) -> tuple[list[str], np.ndarray]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for v in vulnerabilities:
        name    = v.get("component", "unknown")
        version = v.get("version", "")
        comp    = f"{name} {version}" if version else name
        sev  = v.get("base_severity", "info").lower()
        counts[comp][sev] += 1

    # Sort by weighted score descending, then alphabetically for ties.
    def score(comp):
        return sum(_WEIGHTS.get(s, 0) * n for s, n in counts[comp].items())

    components = sorted(counts, key=lambda c: (-score(c), c))[:top]

    matrix = np.array(
        [[counts[comp].get(sev, 0) for sev in _SEVERITIES] for comp in components],
        dtype=float,
    )
    return components, matrix


def _draw(
    components: list[str],
    matrix: np.ndarray,
    firmware_id: str,
    out_path: Path,
) -> None:
    n_rows, n_cols = matrix.shape
    cell_h = 0.45
    fig_h  = max(6, n_rows * cell_h + 2)
    fig, ax = plt.subplots(figsize=(10, fig_h))

    # Build a composite RGBA image: each column uses its own colour map.
    rgba = np.ones((n_rows, n_cols, 4))
    for j, sev in enumerate(_SEVERITIES):
        col_vals = matrix[:, j]
        col_max  = col_vals.max() if col_vals.max() > 0 else 1
        norm     = col_vals / col_max          # 0–1 within this column
        cmap     = plt.get_cmap(_COL_CMAPS[sev])
        # Map 0 → very light tint, 1 → full colour (skip the very-white end).
        for i, v in enumerate(norm):
            rgba[i, j] = cmap(0.15 + 0.85 * v) if col_vals[i] > 0 else (0.97, 0.97, 0.97, 1)

    ax.imshow(rgba, aspect="auto", interpolation="nearest",
              extent=[-0.5, n_cols - 0.5, n_rows - 0.5, -0.5])

    # Cell annotations.
    for i in range(n_rows):
        for j in range(n_cols):
            val = int(matrix[i, j])
            if val > 0:
                # Pick white or dark text for contrast.
                bg = rgba[i, j, :3]
                lum = 0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2]
                txt_col = "white" if lum < 0.45 else "#222222"
                ax.text(j, i, str(val), ha="center", va="center",
                        fontsize=8, color=txt_col, fontweight="bold")

    # Axes.
    ax.set_xticks(range(n_cols))
    ax.set_xticklabels([s.upper() for s in _SEVERITIES], fontsize=9, fontweight="bold")
    ax.xaxis.set_tick_params(length=0)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(components, fontsize=8)
    ax.yaxis.set_tick_params(length=0)

    # Grid lines between cells.
    for x in np.arange(-0.5, n_cols, 1):
        ax.axvline(x, color="white", linewidth=1.5)
    for y in np.arange(-0.5, n_rows, 1):
        ax.axhline(y, color="white", linewidth=1.5)

    total = int(matrix.sum())
    ax.set_title(
        f"{firmware_id} — CVE severity heatmap  ({total} findings, {n_rows} components)",
        fontsize=11, fontweight="bold", pad=12,
    )
    ax.set_xlabel("NVD base severity", fontsize=9, labelpad=8)

    plt.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a CVE severity heatmap from cve_report.json."
    )
    parser.add_argument(
        "analysis_dir", type=Path,
        help="Analysis directory produced by cve.py (must contain cve_report.json).",
    )
    parser.add_argument(
        "--top", "-n", type=int, default=40,
        help="Maximum number of components to show (default: 40, worst-first).",
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output PNG path (default: <analysis_dir>/cve_heatmap.png).",
    )
    args = parser.parse_args()

    analysis_dir = args.analysis_dir.resolve()
    report       = _load_report(analysis_dir)
    firmware_id  = report.get("firmware", analysis_dir.name)
    vulns        = report.get("vulnerabilities", [])

    if not vulns:
        print("[!] No vulnerabilities in report — nothing to plot.")
        sys.exit(0)

    components, matrix = _build_matrix(vulns, args.top)

    out_path = args.output or analysis_dir / "sbom" / "cve_heatmap.png"
    _draw(components, matrix, firmware_id, out_path)

    print(f"[+] Heatmap written → {out_path}")
    print(f"    {len(components)} components × {len(_SEVERITIES)} severity levels  "
          f"({int(matrix.sum())} total findings)")


if __name__ == "__main__":
    main()
