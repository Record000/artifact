import pandas as pd
import matplotlib.pyplot as plt

plt.rcParams['font.size'] = 28
plt.rcParams['axes.titlesize'] = 24
plt.rcParams['axes.labelsize'] = 24
plt.rcParams['xtick.labelsize'] = 22
plt.rcParams['ytick.labelsize'] = 22
plt.rcParams['legend.fontsize'] = 20

df = pd.read_csv("./data/efficient/validator_process.csv")

col_validator = "Validator" if "Validator" in df.columns else "validator"
col_avg = "Average (s)"
col_min = "Min (s)"
col_max = "Max (s)"
col_sd  = "Stddev (s)"

df["mean_ms"] = df[col_avg] * 1000
df["sd_ms"]   = df[col_sd]  * 1000
df["min_ms"]  = df[col_min] * 1000
df["max_ms"]  = df[col_max] * 1000

df = df.sort_values("mean_ms")

fig, ax = plt.subplots(figsize=(10, 4))

for i, row in enumerate(df.itertuples(index=False)):
    pass

for i in range(len(df)):
    mean = df.iloc[i]["mean_ms"]
    sd   = df.iloc[i]["sd_ms"]
    vmin = df.iloc[i]["min_ms"]
    vmax = df.iloc[i]["max_ms"]

    # thin line: min–max
    ax.hlines(i, vmin, vmax, linewidth=5)

    # thick translucent bar: mean ± 1 SD
    ax.hlines(i, mean - sd, mean + sd, linewidth=9, alpha=0.25)

    # dot: mean
    ax.plot(mean, i, marker="o", markersize=9)

ax.set_yticks(range(len(df)))
ax.set_yticklabels(df[col_validator].tolist())
ax.invert_yaxis()

ax.set_xlabel("Per-run processing time (ms)")
# ax.set_title("Validator runtime (mean ± 1 SD, min–max)")
ax.grid(True, axis="x", linestyle="--", linewidth=0.7, alpha=0.5)

plt.tight_layout()

plt.savefig("validator_runtime_dot_whisker.pdf", bbox_inches="tight")
plt.savefig("validator_runtime_dot_whisker.png", dpi=300, bbox_inches="tight")

plt.show()
