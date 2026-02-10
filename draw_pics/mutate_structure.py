import os
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

plt.rcParams['font.size'] = 28
plt.rcParams['axes.titlesize'] = 24
plt.rcParams['axes.labelsize'] = 24
plt.rcParams['xtick.labelsize'] = 22
plt.rcParams['ytick.labelsize'] = 22
plt.rcParams['legend.fontsize'] = 12

DATA_FILES = {
    "FORT": {
        "topo": "./data/structure/mutate_fort.csv",
        "baseline": "./data/structure/baseline_fort.csv",
    },
    "Routinator": {
        "topo": "./data/structure/mutate_routinator.csv",
        "baseline": "./data/structure/baseline_routinator.csv",
    },
    "rpki-client": {
        "topo": "./data/structure/mutate_rpki-client.csv",
        "baseline": "./data/structure/baseline_rpki-client.csv",
    },
    "OctoRPKI": {
        "topo": "./data/structure/mutate_octorpki.csv",
        "baseline": "./data/structure/baseline_octorpki.csv",
    },
}

COL_BBCOUNT = "BB_Count"

def get_script_dir() -> Path:
    try:
        return Path(__file__).resolve().parent
    except NameError:
        # e.g., running in notebook/interactive mode
        return Path.cwd()

SCRIPT_DIR = get_script_dir()
OUT_PDF = SCRIPT_DIR / "bb_count_grouped_box.pdf"

baseline_fill = "#B8C1FF"
baseline_edge = "#2E5BFF"

topo_fill     = "#FFBABA"   # (changed) deeper soft red fill
topo_edge     = "#FF4D4D"   # (changed) deeper soft red edge

point_color   = "#6e6e6e"   # grey outliers/jitter

FIGSIZE = (12, 6.5)
OFFSET = 0.18
BOX_WIDTH = 0.28
JITTER_SIGMA = 0.035
JITTER_SIZE = 7
JITTER_ALPHA = 0.25

VALIDATOR_ORDER = ["Routinator", "rpki-client", "FORT", "OctoRPKI"]

def load_bb_counts(csv_path: str, col_name: str) -> np.ndarray:
    df = pd.read_csv(csv_path)
    if col_name not in df.columns:
        raise ValueError(
            f"Missing column '{col_name}' in {csv_path}. "
            f"Available columns: {list(df.columns)}"
        )
    arr = pd.to_numeric(df[col_name], errors="coerce").dropna().to_numpy()
    if len(arr) == 0:
        raise ValueError(f"No valid numeric values in column '{col_name}' for {csv_path}.")
    return arr

def main():
    validators = []
    base_arrays = []
    topo_arrays = []

    for v in VALIDATOR_ORDER:
        paths = DATA_FILES.get(v, {})
        base_path = paths.get("baseline", "")
        topo_path = paths.get("topo", "")

        if not (base_path and topo_path and os.path.exists(base_path) and os.path.exists(topo_path)):
            print(f"[skip] {v}: missing baseline/topo file. baseline='{base_path}', topo='{topo_path}'")
            continue

        base = load_bb_counts(base_path, COL_BBCOUNT)
        topo = load_bb_counts(topo_path, COL_BBCOUNT)

        validators.append(v)
        base_arrays.append(base)
        topo_arrays.append(topo)

    if not validators:
        raise RuntimeError("No valid validator pairs found. Please set correct file paths in DATA_FILES.")

    centers = np.arange(len(validators))
    pos_b = centers - OFFSET
    pos_t = centers + OFFSET

    fig, ax = plt.subplots(figsize=FIGSIZE)

    # Baseline boxplot
    ax.boxplot(
        base_arrays, positions=pos_b, widths=BOX_WIDTH, patch_artist=True, showfliers=True,
        boxprops=dict(facecolor=baseline_fill, edgecolor=baseline_edge, linewidth=1.2, alpha=0.75),
        whiskerprops=dict(color=baseline_edge, linewidth=1.2),
        capprops=dict(color=baseline_edge, linewidth=1.2),
        medianprops=dict(color="black", linewidth=1.2),
        flierprops=dict(marker="s", markersize=2.2,
                        markerfacecolor=point_color, markeredgecolor=point_color, alpha=0.55),
    )

    # Topo boxplot
    ax.boxplot(
        topo_arrays, positions=pos_t, widths=BOX_WIDTH, patch_artist=True, showfliers=True,
        boxprops=dict(facecolor=topo_fill, edgecolor=topo_edge, linewidth=1.2, alpha=0.75),
        whiskerprops=dict(color=topo_edge, linewidth=1.2),
        capprops=dict(color=topo_edge, linewidth=1.2),
        medianprops=dict(color="black", linewidth=1.2),
        flierprops=dict(marker="s", markersize=2.2,
                        markerfacecolor=point_color, markeredgecolor=point_color, alpha=0.55),
    )

    # Grey jitter points
    rng = np.random.default_rng(0)
    for x, arr in zip(pos_b, base_arrays):
        ax.scatter(rng.normal(x, JITTER_SIGMA, size=len(arr)), arr,
                   s=JITTER_SIZE, alpha=JITTER_ALPHA, color=point_color, edgecolors="none")
    for x, arr in zip(pos_t, topo_arrays):
        ax.scatter(rng.normal(x, JITTER_SIGMA, size=len(arr)), arr,
                   s=JITTER_SIZE, alpha=JITTER_ALPHA, color=point_color, edgecolors="none")

    ax.set_xticks(centers)
    ax.set_xticklabels(validators)
    ax.set_ylabel("Total BB executions per run", fontweight="bold")
    # ax.set_title("Total BB Executions: Baseline vs Topology Mutation", fontweight="bold")
    ax.grid(True, axis="y", alpha=0.25)

    legend_handles = [
        Patch(facecolor=baseline_fill, edgecolor=baseline_edge, alpha=0.75, label="CURE-like (fixed structure)"),
        Patch(facecolor=topo_fill, edgecolor=topo_edge, alpha=0.75, label="Structure Mutation"),
    ]
    ax.legend(handles=legend_handles, loc="upper right", frameon=True)

    plt.tight_layout()

    plt.show()

    fig.savefig(OUT_PDF, format="pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"[ok] Saved PDF to: {OUT_PDF}")

if __name__ == "__main__":
    main()
