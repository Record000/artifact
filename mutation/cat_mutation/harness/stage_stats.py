#!/usr/bin/env python3
"""Aggregate stage-reach statistics for a campaign directory.

Usage: python3 stage_stats.py <results_dir> [--csv out.csv]

Per validator:
  - P(reach stage k)  = #repos with max_stage >= k / N   (k = 1..5)
  - final-stage distribution (max_stage histogram)
  - avg STAGE_k marker hits per repo
"""
import argparse
import glob
import json
import os
from collections import Counter

STAGES = [1, 2, 3, 4, 5]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir")
    ap.add_argument("--csv", type=str, default="")
    a = ap.parse_args()

    repos = []
    for p in sorted(glob.glob(os.path.join(a.results_dir, "repo_*", "result.json"))):
        with open(p) as f:
            repos.append(json.load(f))

    n = len(repos)
    if n == 0:
        print("no result.json found under", a.results_dir)
        return
    gen_ok = sum(1 for r in repos if r.get("gen_ok"))
    print(f"repos={n} (gen_ok={gen_ok})\n")

    validators = sorted({v for r in repos for v in r.get("validators", {})})
    lines = ["validator,repos,gen_ok," + ",".join(f"P(stage>={k})" for k in STAGES)
             + "," + ",".join(f"final_{k}" for k in [0] + STAGES) + ",avg_markers"]

    for v in validators:
        vs = [r["validators"][v] for r in repos if v in r.get("validators", {})]
        m = len(vs)
        reach = {k: sum(1 for x in vs if x["max_stage"] >= k) / m for k in STAGES}
        dist = Counter(x["max_stage"] for x in vs)
        avg_hits = {k: sum(x["stage_hits"].get(str(k), x["stage_hits"].get(k, 0)) for x in vs) / m for k in STAGES}
        avg_markers = sum(x["n_markers"] for x in vs) / m

        print(f"== {v} (n={m})")
        for k in STAGES:
            print(f"   P(reach stage {k}) = {reach[k]*100:6.1f}%   avg STAGE_{k} hits/repo = {avg_hits[k]:.2f}")
        print("   final-stage distribution:")
        for k in [0] + STAGES:
            print(f"     stage {k}: {dist.get(k,0):4d} ({dist.get(k,0)/m*100:.1f}%)")
        print()
        lines.append(",".join([v, str(m), str(gen_ok)]
                              + [f"{reach[k]:.4f}" for k in STAGES]
                              + [str(dist.get(k, 0)) for k in [0] + STAGES]
                              + [f"{avg_markers:.2f}"]))

    if a.csv:
        with open(a.csv, "w") as f:
            f.write("\n".join(lines) + "\n")
        print("csv written:", a.csv)


if __name__ == "__main__":
    main()
