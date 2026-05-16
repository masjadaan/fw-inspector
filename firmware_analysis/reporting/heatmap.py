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

# One colour scale per severity column so intensity encodes count within column.
_COL_CMAPS = {
    "critical": "Reds",
    "high":     "Oranges",
    "medium":   "YlOrBr",
    "low":      "Blues",
    "info":     "Greens",
    "esc":      "RdPu",
    "score":    "Purples",
}

# Library variants that share CVEs with their upstream package.
_NAME_ALIASES: dict[str, str] = {
    "libcrypto":  "openssl",
    "libssl":     "openssl",
    "ld-uClibc":  "uClibc",
    "libcrypt":   "uClibc",
    "libdl":      "uClibc",
    "libm":       "uClibc",
    "libnsl":     "uClibc",
    "libpthread": "uClibc",
    "libresolv":  "uClibc",
    "librt":      "uClibc",
    "libuClibc":  "uClibc",
    "libutil":    "uClibc",
}

import re as _re
_VERSION_SUFFIX = _re.compile(r"-(\d[\d.]+)$")


def _canonical(name: str, version: str) -> str:
    """Map library variants to their upstream package label, deduplicating by CVE."""
    m = _VERSION_SUFFIX.search(name)
    if m and not version:
        version = m.group(1)
        name = name[: m.start()]
    canonical_name = _NAME_ALIASES.get(name, name)
    # Normalise "openssl 1.0" → "openssl 1.0.0" so all three variants land on one row.
    if canonical_name == "openssl" and version in ("1.0", "1.0.0"):
        version = "1.0.0"
    return f"{canonical_name} {version}".strip() if version else canonical_name


def _load_report(analysis_dir: Path) -> dict:
    path = analysis_dir / "sbom" / "cve_report.json"
    if not path.exists():
        print(f"[!] {path} not found.  Run cve.py first.")
        sys.exit(1)
    return json.loads(path.read_text())


def _build_matrix(
    vulnerabilities: list[dict], top: int
) -> tuple[list[str], np.ndarray, list[float], list[int], list[str]]:
    # Deduplicate: canonical_label → cve_id → (severity, cvss_score, network_reachable, escalated).
    cve_data: dict[str, dict[str, tuple[str, float, bool, bool]]] = defaultdict(dict)
    for v in vulnerabilities:
        label  = _canonical(v.get("component", "unknown"), v.get("version", ""))
        cve_id = v.get("cve", "unknown")
        incoming_reachable = bool(v.get("network_reachable", False))
        incoming_escalated = bool(v.get("escalated", False))
        if cve_id not in cve_data[label]:
            cve_data[label][cve_id] = (
                v.get("adjusted_severity", v.get("base_severity", "info")).lower(),
                float(v.get("cvss_score", 0.0)),
                incoming_reachable,
                incoming_escalated,
            )
        else:
            sev, cvss, reachable, escalated = cve_data[label][cve_id]
            cve_data[label][cve_id] = (
                sev, cvss,
                reachable or incoming_reachable,
                escalated or incoming_escalated,
            )

    # Severity counts from deduplicated CVEs.
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for label, cves in cve_data.items():
        for sev, _, _, _ in cves.values():
            counts[label][sev] += 1

    def score(comp: str) -> float:
        return sum(
            cvss * (1.5 if reachable else 1.0)
            for _, cvss, reachable, _ in cve_data[comp].values()
        )

    components      = sorted(cve_data, key=lambda c: (-score(c), c))[:top]
    scores          = [round(score(c), 1) for c in components]
    escalated_counts = [
        sum(1 for _, _, _, esc in cve_data[c].values() if esc)
        for c in components
    ]

    active_sevs = [s for s in _SEVERITIES if any(counts[c].get(s, 0) > 0 for c in components)]
    matrix = np.array(
        [[counts[comp].get(sev, 0) for sev in active_sevs] for comp in components],
        dtype=float,
    )
    return components, matrix, scores, escalated_counts, active_sevs


def _draw(
    components: list[str],
    matrix: np.ndarray,
    scores: list[float],
    escalated_counts: list[int],
    active_sevs: list[str],
    firmware_id: str,
    out_path: Path,
) -> None:
    n_rows, n_sev_cols = matrix.shape
    all_cols   = active_sevs + ["esc", "score"]
    col_labels = [s.upper() for s in active_sevs] + ["ESC", "SCORE"]
    n_cols     = len(all_cols)

    esc_col   = np.array(escalated_counts, dtype=float).reshape(-1, 1)
    score_col = np.array(scores, dtype=float).reshape(-1, 1)
    extended  = np.hstack([matrix, esc_col, score_col])

    cell_h = 0.45
    fig_h  = max(6, n_rows * cell_h + 2)
    fig, ax = plt.subplots(figsize=(11, fig_h))

    # Build a composite RGBA image: each column uses its own colour map.
    rgba = np.ones((n_rows, n_cols, 4))
    for j, col in enumerate(all_cols):
        col_vals = extended[:, j]
        col_max  = col_vals.max() if col_vals.max() > 0 else 1
        norm     = col_vals / col_max
        cmap     = plt.get_cmap(_COL_CMAPS[col])
        for i, v in enumerate(norm):
            rgba[i, j] = cmap(0.15 + 0.85 * v) if col_vals[i] > 0 else (0.97, 0.97, 0.97, 1)

    ax.imshow(rgba, aspect="auto", interpolation="nearest",
              extent=[-0.5, n_cols - 0.5, n_rows - 0.5, -0.5])

    # Cell annotations.
    for i in range(n_rows):
        for j in range(n_cols):
            val = int(extended[i, j])
            if val > 0:
                bg      = rgba[i, j, :3]
                lum     = 0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2]
                txt_col = "white" if lum < 0.45 else "#222222"
                ax.text(j, i, str(val), ha="center", va="center",
                        fontsize=8, color=txt_col, fontweight="bold")

    # Axes.
    ax.set_xticks(range(n_cols))
    ax.set_xticklabels(col_labels, fontsize=9, fontweight="bold")
    ax.xaxis.set_tick_params(length=0)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(components, fontsize=8)
    ax.yaxis.set_tick_params(length=0)

    # Thicker separators before ESC and SCORE columns.
    ax.axvline(n_sev_cols - 0.5,     color="white", linewidth=3)
    ax.axvline(n_sev_cols + 1 - 0.5, color="white", linewidth=3)

    # Grid lines between cells.
    for x in np.arange(-0.5, n_cols, 1):
        ax.axvline(x, color="white", linewidth=1.5)
    for y in np.arange(-0.5, n_rows, 1):
        ax.axhline(y, color="white", linewidth=1.5)

    total = int(matrix.sum())
    ax.set_title(
        f"{firmware_id} — CVE severity heatmap  ({total} unique findings, {n_rows} components)",
        fontsize=11, fontweight="bold", pad=12,
    )
    ax.set_xlabel("NVD base severity  ·  SCORE = Σ CVSS scores (×1.5 if network-reachable)",
                  fontsize=8, labelpad=8)

    plt.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def _write_csv(
    components: list[str],
    matrix: np.ndarray,
    scores: list[float],
    escalated_counts: list[int],
    active_sevs: list[str],
    out_path: Path,
) -> None:
    import csv
    headers = ["component"] + [s.upper() for s in active_sevs] + ["ESCALATED", "SCORE"]
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for i, comp in enumerate(components):
            row = [comp] + [int(matrix[i, j]) for j in range(len(active_sevs))]
            row += [escalated_counts[i], scores[i]]
            w.writerow(row)


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
    parser.add_argument(
        "--csv", action="store_true",
        help="Also write a companion CSV alongside the PNG.",
    )
    args = parser.parse_args()

    analysis_dir = args.analysis_dir.resolve()
    report       = _load_report(analysis_dir)
    firmware_id  = report.get("firmware", analysis_dir.name)
    vulns        = report.get("vulnerabilities", [])

    if not vulns:
        print("[!] No vulnerabilities in report — nothing to plot.")
        sys.exit(0)

    components, matrix, scores, escalated_counts, active_sevs = _build_matrix(vulns, args.top)

    out_path = args.output or analysis_dir / "sbom" / "cve_heatmap.png"
    _draw(components, matrix, scores, escalated_counts, active_sevs, firmware_id, out_path)

    print(f"[+] Heatmap written → {out_path}")
    print(f"    {len(components)} components × {len(_SEVERITIES)} severity levels  "
          f"({int(matrix.sum())} unique findings, deduplicated by CVE ID)")

    if args.csv:
        csv_path = out_path.with_suffix(".csv")
        _write_csv(components, matrix, scores, escalated_counts, active_sevs, csv_path)
        print(f"[+] CSV written    → {csv_path}")


if __name__ == "__main__":
    main()
