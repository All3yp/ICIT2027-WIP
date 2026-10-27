#!/usr/bin/env python3
"""Generate the inactivity figure from the recorded artifacts.

Figure 1 reports the measured inactivity transitions (E2) as horizontal bars whose labels sit
outside the marks: time from establishment to the responder's stale transition for the default
timers, for two injected RTT values, and under the guarded responder.

The figure is written as PDF (vector, TrueType fonts) and PNG (300 dpi) under
`figures/`. Every text label is checked for overlapping another label, for leaving the
axes, and for sitting on top of a drawn mark; the script exits non-zero if any check fails.

Run: uv run --with matplotlib python lab/make_figures.py
"""
from __future__ import annotations

import argparse
import itertools
import json
from statistics import median
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
# IEEE asks for Type 1 or TrueType fonts in the final PDF; matplotlib's default is Type 3.
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
matplotlib.rcParams.update({
    "font.family": "serif",
    "font.serif": ["DejaVu Serif"],
    "font.size": 8,
    "axes.titlesize": 8,
    "axes.labelsize": 8,
    "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5,
    "axes.linewidth": 0.6,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "hatch.linewidth": 0.5,
    "text.color": "#1b1b1b",
})
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch

INK = "#1b1b1b"
GUARD = "#1a6f1a"
DEFECT = "#a01b1b"
MUTED = "#4d4d4d"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _texts(ax):
    out = [t for t in ax.texts if t.get_text().strip()]
    out += [t for t in ax.get_xticklabels() + ax.get_yticklabels() if t.get_text().strip()]
    for label in (ax.xaxis.label, ax.yaxis.label, ax.title):
        if label.get_text().strip():
            out.append(label)
    return out


def check_figure(fig, axes, name: str) -> list[str]:
    """Return label overlaps, out-of-axes annotations and annotations drawn on top of marks."""
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    problems: list[str] = []
    for ax in axes:
        boxes = [(t.get_text().strip(), t.get_window_extent(renderer)) for t in _texts(ax)]
        for (a_text, a_box), (b_text, b_box) in itertools.combinations(boxes, 2):
            if a_box.overlaps(b_box):
                problems.append(f"{name}: label {a_text!r} overlaps label {b_text!r}")
        # Only free-standing annotations must stay inside the axes; tick and axis labels
        # legitimately sit outside it.
        axes_box = ax.get_window_extent(renderer)
        annotations = [(t.get_text().strip(), t.get_window_extent(renderer))
                       for t in ax.texts if t.get_text().strip()]
        for text, box in annotations:
            if (box.x0 < axes_box.x0 - 1 or box.y0 < axes_box.y0 - 1
                    or box.x1 > axes_box.x1 + 1 or box.y1 > axes_box.y1 + 1):
                problems.append(f"{name}: label {text!r} leaves the axes")
        for patch in ax.patches:
            try:
                patch_box = patch.get_window_extent(renderer)
            except Exception:
                continue
            if patch_box.width <= 1 or patch_box.height <= 1:
                continue
            for text, box in annotations:
                if box.overlaps(patch_box):
                    problems.append(f"{name}: label {text!r} is drawn on a mark")
    return problems



def figure_inactivity(experiments: dict, path_pdf: Path, path_png: Path) -> list[str]:
    e2 = experiments["E2"]
    rows = [
        ("default timers", "E2base", INK, "—"),
        ("probe, rtt 0.075 s", "E2mid", DEFECT, None),
        ("probe, rtt 2.0 s", "E2huge", DEFECT, None),
        ("guarded, rtt 0.075 s", "E2guard", GUARD, None),
    ]

    fig, ax = plt.subplots(figsize=(3.5, 2.05))
    fig.subplots_adjust(left=0.36, right=0.985, top=0.90, bottom=0.20)
    xmax = 70.0

    for pos, (label, trial, colour, _) in enumerate(rows):
        runs = e2[trial]["time_to_stale_seconds"]
        window = e2[trial]["window_seconds"]
        if runs:
            value = median(runs)
            ax.barh(pos, value, height=0.58, color=colour, linewidth=0)
            ax.text(value + 1.4, pos, f"{value:.1f} s (n={len(runs)})", va="center", ha="left",
                    fontsize=7.6, color=colour)
        else:
            ax.barh(pos, window, height=0.58, facecolor="white", edgecolor=colour,
                    linewidth=0.9, hatch="///")
            ax.text(window + 1.4, pos, "not reached", va="center", ha="left",
                    fontsize=7.6, color=colour)

    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([r[0] for r in rows])
    ax.invert_yaxis()
    ax.set_xlim(0, xmax)
    ax.set_ylim(len(rows) - 0.45, -0.65)
    ax.set_xticks([0, 15, 30, 45, 60])
    ax.set_xlabel("time to responder STALE (s)")
    ax.grid(axis="x", linewidth=0.3, color="#e2e2e2")
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)

    conflicts = check_figure(fig, [ax], "fig2")
    # Fixed metadata so that regenerating the figure produces an identical file.
    fig.savefig(path_pdf, metadata={"CreationDate": None, "ModDate": None, "Producer": None,
                                    "Creator": None})
    fig.savefig(path_png, dpi=300)
    plt.close(fig)
    return conflicts


def main() -> None:
    parser = argparse.ArgumentParser()
    repo = Path(__file__).resolve().parent.parent
    parser.add_argument("--experiments", type=Path, default=repo / "results" / "experiments_summary.json")
    parser.add_argument("--outdir", type=Path, default=repo / "figures")
    args = parser.parse_args()
    args.outdir.mkdir(parents=True, exist_ok=True)

    experiments = load_json(args.experiments)
    problems = figure_inactivity(experiments,
                                 args.outdir / "fig1_inactivity.pdf",
                                 args.outdir / "fig1_inactivity.png")
    report = {
        "figures": sorted(p.name for p in args.outdir.iterdir() if p.suffix in {".pdf", ".png"}),
        "source_experiments": str(args.experiments),
        "overlap_check": "PASS" if not problems else "FAIL",
        "problems": problems,
    }
    (args.outdir / "figure_report.json").write_text(json.dumps(report, indent=2) + "\n",
                                                    encoding="utf-8")
    print(f"overlap_check: {report['overlap_check']} ({len(problems)} problems)")
    if problems:
        raise SystemExit("figure check failed")


if __name__ == "__main__":
    main()
