import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from matplotlib.patches import Patch

# 全局字体设置
plt.rcParams['font.size'] = 28          # 默认字体
plt.rcParams['axes.titlesize'] = 24     # 子图标题
plt.rcParams['axes.labelsize'] = 24     # 轴标签
plt.rcParams['xtick.labelsize'] = 22    # x轴刻度
plt.rcParams['ytick.labelsize'] = 22    # y轴刻度
plt.rcParams['legend.fontsize'] = 20    # 图例

# =========================
# Hard-coded inputs
# =========================
RUN_CSVS = [
    "./data/diversity/run1.csv",
    "./data/diversity/run2.csv",
    "./data/diversity/run3.csv",
    "./data/diversity/run4.csv",
    # "./data/diversity/run5.csv",
]
OUTPUT_PDF = "euclid_facets_2x2.pdf"

METRIC_COLS = ["depth", "num_ca", "num_roa", "num_mft", "num_crl", "num_cert"]
COUNT_COLS  = ["num_ca", "num_roa", "num_mft", "num_crl", "num_cert"]

RNG_SEED = 1
MAX_POINTS_PER_RUN = 1000
JITTER = 0.35

# Colors per run (run1..run4 used)
RUN_COLORS = ["tab:red", "tab:orange", "tab:green", "tab:purple", "tab:brown"]


def euclid_scores_one_run(df_metrics: pd.DataFrame) -> np.ndarray:
    X = df_metrics.astype(float).copy()

    # log1p for count-like metrics (heavy-tailed)
    for c in COUNT_COLS:
        X[c] = np.log1p(X[c])

    Z = X.to_numpy(dtype=float)

    # standardize per dimension within the run
    mu = Z.mean(axis=0)
    sigma = Z.std(axis=0, ddof=0)
    sigma[sigma == 0] = 1.0
    Zs = (Z - mu) / sigma

    # centroid in standardized space
    centroid = Zs.mean(axis=0)

    # Euclidean distance to centroid
    return np.linalg.norm(Zs - centroid, axis=1)


def main():
    rng = np.random.default_rng(RNG_SEED)

    # ---- 2x2 panels: only use run1..run4 ----
    csvs_to_plot = RUN_CSVS[:4]
    colors_to_plot = RUN_COLORS[:4]

    runs_scores = []
    for csv_path in csvs_to_plot:
        df = pd.read_csv(csv_path)

        missing = [c for c in METRIC_COLS if c not in df.columns]
        if missing:
            raise ValueError(
                f"Missing columns {missing} in {csv_path}. "
                f"Available columns: {list(df.columns)}"
            )

        runs_scores.append(euclid_scores_one_run(df[METRIC_COLS].copy()))

    # shared x-limits (robust to outliers)
    all_scores = np.concatenate(runs_scores)
    x_min, x_max = np.percentile(all_scores, 0.5), np.percentile(all_scores, 99.5)

    # ---- plot: 2x2 facets scatter ----
    fig, axes = plt.subplots(2, 2, figsize=(12, 8), sharey=True)
    axes_flat = axes.ravel()

    for i, (ax, scores) in enumerate(zip(axes_flat, runs_scores), start=1):
        scores = np.asarray(scores)

        # subsample for readability
        if len(scores) > MAX_POINTS_PER_RUN:
            idx = rng.choice(len(scores), size=MAX_POINTS_PER_RUN, replace=False)
            scores_plot = scores[idx]
        else:
            scores_plot = scores

        # vertical jitter only to reduce overlap (no semantic meaning)
        y = rng.uniform(-JITTER, JITTER, size=len(scores_plot))
        ax.scatter(scores_plot, y, s=8, alpha=0.35, c=colors_to_plot[i - 1])

        # remove per-panel title "runX"
        ax.set_title("")
        ax.set_yticks([])
        ax.set_xlim(x_min, x_max)
        ax.set_xlabel("")

    # =========================
    # Layout tweaks you asked:
    # 1) Move "Euclid score" closer to x-axis  -> increase y a bit
    # =========================
    fig.supxlabel("Euclid score", y=0.10, x=0.53)  # (default is often lower; 0.05~0.08 都可微调)

    # =========================
    # 2) Move global y-label "jitter" closer to y-axis -> increase x a bit
    # =========================
    fig.text(0.055, 0.55, "jitter", rotation="vertical", va="center")  # 0.04~0.07 可微调

    # ---- global legend for run colors (run1..run4), top-center but LOWER ----
    legend_handles = [
        Patch(facecolor=colors_to_plot[i], edgecolor="black", alpha=0.6, label=f"run {i+1}")
        for i in range(4)
    ]
    fig.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.97),  # 往下：0.95~0.98 之间调
        ncol=4,
        frameon=True,
        title=None,
    )

    # leave room for top legend and left global y-label
    plt.tight_layout(rect=(0.07, 0.08, 0.98, 0.92))
    #                 ^^^^  ^^^^             ^^^^
    #                left bottom            top
    # bottom=0.08 让 supxlabel 更靠近轴；top=0.92 给 legend 留空间

    out_path = Path(OUTPUT_PDF)
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    print(f"Saved: {out_path.resolve()}")

    plt.show()
    plt.close(fig)


if __name__ == "__main__":
    main()
