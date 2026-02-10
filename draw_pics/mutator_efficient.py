import pandas as pd
import matplotlib.pyplot as plt

# 全局字体设置
plt.rcParams['font.size'] = 28          # 默认字体
plt.rcParams['axes.titlesize'] = 24     # 子图标题
plt.rcParams['axes.labelsize'] = 24     # 轴标签
plt.rcParams['xtick.labelsize'] = 22    # x轴刻度
plt.rcParams['ytick.labelsize'] = 22    # y轴刻度
plt.rcParams['legend.fontsize'] = 20    # 图例

# ----------------------
# Input files (CSV)
# ----------------------
# mutator_times.csv columns: workers, ours_s, scaffolding_s
# validator_avgs.csv columns: validator, avg_s
MUTATOR_CSV = "./data/efficient/mutator_times.csv"
VALIDATOR_CSV = "./data/efficient/validator_avgs.csv"

# ----------------------
# Read data
# ----------------------
mut_df = pd.read_csv(MUTATOR_CSV)
val_df = pd.read_csv(VALIDATOR_CSV)

# Basic checks / cleanup
required_mut_cols = {"workers", "ours_s", "scaffolding_s"}
required_val_cols = {"validator", "avg_s"}

missing_mut = required_mut_cols - set(mut_df.columns)
missing_val = required_val_cols - set(val_df.columns)
if missing_mut:
    raise ValueError(f"{MUTATOR_CSV} missing columns: {sorted(missing_mut)}")
if missing_val:
    raise ValueError(f"{VALIDATOR_CSV} missing columns: {sorted(missing_val)}")

mut_df = mut_df.sort_values("workers")

workers = mut_df["workers"].tolist()
ours_s = mut_df["ours_s"].tolist()
scaffolding_s = mut_df["scaffolding_s"].tolist()

overall_rp_avg = val_df["avg_s"].mean()

# ----------------------
# Paper-friendly palette (no black, colorblind-friendly)
# ----------------------
COLOR_MUT = "#0072B2"      # blue
COLOR_SCAF = "#D55E00"     # vermillion
COLOR_RPAVG = "#009E73"    # bluish green

# ----------------------
# Plot (show first, then save as PDF)
# ----------------------
fig, ax = plt.subplots(figsize=(11, 6.5))

ax.plot(
    workers, ours_s,
    marker="o", linewidth=5.0, markersize=10,
    color=COLOR_MUT,
    label="Grammar+Repair Mutator"
)
ax.plot(
    workers, scaffolding_s,
    marker="s", linewidth=5.0, markersize=10,
    color=COLOR_SCAF,
    label="Scaffolding (CURE-like)"
)

ax.axhline(
    overall_rp_avg,
    linestyle="--",
    linewidth=3.0,
    color=COLOR_RPAVG,
    label="Validators avg (mean of 4)"
)

ax.set_xlabel("Mutator workers")
ax.set_ylabel("Seconds per repository")
ax.set_xticks(workers)

# Minimal paper-like cosmetics
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.grid(True, axis="y", linestyle=":", linewidth=0.8, alpha=0.6)

ax.legend()
fig.tight_layout()

# 1) Show first
plt.show()

# 2) Save as PDF after showing
out_pdf = "figA_linechart.pdf"
fig.savefig(out_pdf)

print("Saved to:", out_pdf)
print(f"Overall validators average: {overall_rp_avg:.6f} s/repo")