import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

plt.rcParams['font.size'] = 30
plt.rcParams['axes.titlesize'] = 30
plt.rcParams['axes.labelsize'] = 28
plt.rcParams['xtick.labelsize'] = 30
plt.rcParams['ytick.labelsize'] = 30
plt.rcParams['legend.fontsize'] = 30

def find_stage_cols(cols):
    """Find columns for stage_0..stage_5 (case-insensitive, with some fallbacks)."""
    lower = {c.lower(): c for c in cols}
    stage_cols = []
    for i in range(6):
        key = f"stage_{i}"
        if key in lower:
            stage_cols.append(lower[key])
        else:
            # fallback names if your CSV uses different style
            for ak in [f"stage{i}", f"stage-{i}", f"s{i}", f"stg{i}", f"stage {i}"]:
                if ak in lower:
                    stage_cols.append(lower[ak])
                    break
            else:
                raise ValueError(f"Missing column for stage {i}. Available: {list(cols)}")
    return stage_cols

def compute_cumulative_passrate(csv_path):
    """
    Return (stage_labels, series_dict)
    series_dict maps method_name -> np.array of cumulative reach probabilities for stage_0..stage_5.

    The code auto-detects whether the stage columns are:
      - already cumulative (stage_0 ~ 1 and non-increasing), OR
      - a terminal-stage distribution (counts/percent/prob), then converts to cumulative:
            reach(stage_i) = 1 - sum_{j<i} terminal(stage_j)
    """
    df = pd.read_csv(csv_path)
    df = df.rename(columns={df.columns[0]: "method"})  # first column = method name
    stage_cols = find_stage_cols(df.columns)

    # Heuristic: decide if stage columns already look cumulative
    v0 = df.loc[0, stage_cols].astype(float).values
    looks_like_cum = (
        (v0[0] >= 0.95) and
        np.all(np.diff(v0) <= 1e-6) and
        (v0.sum() > 1.2) and
        (v0.max() <= 1.5)  # avoid e.g. 0..100 scale
    )

    out = {}
    for _, row in df.iterrows():
        m = str(row["method"]).strip()
        v = row[stage_cols].astype(float).values

        if looks_like_cum:
            cum = v.copy()
            if cum.max() > 1.5:  # if in 0..100
                cum = cum / 100.0
        else:
            # treat as terminal distribution and normalize
            s = v.sum()
            if s <= 0:
                cum = np.zeros_like(v)
            else:
                v = v / s
                cumsum_before = np.concatenate([[0.0], np.cumsum(v[:-1])])
                cum = 1.0 - cumsum_before

        out[m] = cum

    stage_labels = [f"stage_{i}" for i in range(6)]
    return stage_labels, out


REPAIR_COLOR = "#009E73"
NOREPAIR_COLOR = "#CC79A7"

def style_for_method(method_name: str):
    n = method_name.lower()
    if ("w/o" in n) or ("without" in n) or ("no repair" in n) or ("no_repair" in n) or ("norepair" in n):
        return dict(linestyle="--", color=NOREPAIR_COLOR, label="CURE-like (no repair)")
    if "repair" in n:
        return dict(linestyle="-", color=REPAIR_COLOR, label="With repair")
    return dict(linestyle="-", color=None, label=method_name)


rps = [
    ("Routinator",  "./data/stage/routinator.csv"),
    ("rpki-client", "./data/stage/rpki-client.csv"),
    ("FORT",        "./data/stage/fort.csv"),
    ("OctoRPKI",    "./data/stage/octorpki.csv"),
]

fig, axes = plt.subplots(1, 4, figsize=(48, 8), sharex=True, sharey=True)
axes = axes.flatten()

legend_handles, legend_labels = None, None

for idx, (rp_name, path) in enumerate(rps):
    ax = axes[idx]
    stages, series = compute_cumulative_passrate(path)
    x = np.arange(len(stages))

    methods = list(series.keys())
    methods_sorted = sorted(
        methods,
        key=lambda m: 0 if ("repair" in m.lower()
                            and "w/o" not in m.lower()
                            and "without" not in m.lower()
                            and "no repair" not in m.lower()) else 1
    )

    handles, labels = [], []
    for m in methods_sorted:
        st = style_for_method(m)
        line, = ax.plot(
            x, series[m],
            linewidth=6.2,
            markersize=10.0,
            marker="o",
            linestyle=st["linestyle"],
            color=st["color"],
        )
        handles.append(line)
        labels.append(st["label"])

    if legend_handles is None:
        legend_handles, legend_labels = handles, labels

    ax.text(0.5, -0.15, rp_name, transform=ax.transAxes,
            ha="center", va="top", fontweight="bold", fontsize=38)

    ax.set_xticks(x)
    ax.set_xticklabels(stages)
    ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.grid(True, axis="y", linewidth=0.6, alpha=0.35)

    ax.tick_params(axis="x", which="both", labelbottom=True, pad=12)
    ax.tick_params(axis="y", which="both", labelleft=True, pad=12)

fig.text(0.01, 0.5, "Cumulative pass rate (%)", rotation="vertical", va="center")

for ax in axes:
    ax.set_xlabel("")

leg = fig.legend(
    legend_handles, legend_labels,
    frameon=True, fancybox=False,
    ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.01),
)
leg.get_frame().set_linewidth(0.8)

plt.subplots_adjust(left=0.05, right=0.99, top=0.85, bottom=0.18, wspace=0.18)

plt.savefig("multi_rp_multistage_2x2_adjusted.png", dpi=300, bbox_inches="tight")
plt.savefig("multi_rp_multistage_2x2_adjusted.pdf", bbox_inches="tight")
plt.show()
