#!/usr/bin/env python3
"""Prepare a new external workspace; does not start daemons or experiments."""
import argparse
from pathlib import Path
import shutil
ap=argparse.ArgumentParser()
ap.add_argument('workspace',type=Path)
ap.add_argument('--runtime',type=Path,default=Path('/home/xyf/research/RPKI/exp_cureasn1'))
a=ap.parse_args()
src=Path(__file__).resolve().parent
out=a.workspace.expanduser().resolve()
artifact=src.parents[1]
if out == artifact or artifact in out.parents:
    ap.error('workspace must be outside artifact')
if out.exists():
    ap.error('workspace must not already exist')
runtime=a.runtime.resolve()
for name in ['rp_bins','glibc239','harness/.venv','batch_mutator/target/release/batch_mutator']:
    if not (runtime/name).exists():
        ap.error('missing runtime dependency: '+str(runtime/name))
out.mkdir(parents=True)
for name in ['harness','batch_mutator','vendor']:
    shutil.copytree(src/name,out/name)
for name in ['rp_bins','glibc239']:
    (out/name).symlink_to(runtime/name,target_is_directory=True)
(out/'harness/.venv').symlink_to(runtime/'harness/.venv',target_is_directory=True)
(out/'batch_mutator/target/release').mkdir(parents=True)
(out/'batch_mutator/target/release/batch_mutator').symlink_to(runtime/'batch_mutator/target/release/batch_mutator')
(out/'results').mkdir()
(out/'harness/rsyncd.exp.conf').write_text(
    f'pid file = {out}/rsyncd.pid\nlock file = {out}/rsyncd.lock\n'
    f'port = 8730\naddress = 127.0.0.1\nuse chroot = no\nread only = yes\nlist = yes\n'
    f'[myrpki]\npath = {out}/harness/mutation/out/my_repo\n')
print('Prepared:',out)
print('No daemon or experiment started. Check port 8730 and README before running.')
