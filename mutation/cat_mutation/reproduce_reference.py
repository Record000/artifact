#!/usr/bin/env python3
"""Recompute the published table from historical per-repository summaries.
This does not run validators. Source: exp_cureasn1/results/fix_cure_v2 (1000 repos).
Usage: python3 reproduce_reference.py /tmp/cat-reference
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('output',type=Path)
a=ap.parse_args(); src=Path(__file__).resolve().parent; out=a.output.resolve()
artifact=src.parents[1]
if out==artifact or artifact in out.parents: ap.error('output must be outside artifact')
if out.exists(): ap.error('output must not exist')
with tarfile.open(src/'reference_results.tar.gz') as tar:
    rows=[]
    for m in tar.getmembers():
        parts=Path(m.name).parts
        if not m.isfile() or len(parts)!=2 or not parts[0].startswith('repo_') or parts[1]!='result.json':
            ap.error('unexpected archive member')
        data=tar.extractfile(m).read(); json.loads(data); rows.append((parts,data))
    if len(rows)!=1000: ap.error('expected 1000 records')
    for parts,data in rows:
        dest=out.joinpath(*parts); dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(data)
subprocess.run([sys.executable,str(src/'harness/stage_stats.py'),str(out),'--csv',str(out/'cat_mutation_stats.csv')],check=True)
