#!/usr/bin/env python3
"""Prepare an independent workspace on Linux x86_64 (glibc >= 2.39).
Requires Python >= 3.10, venv/pip, Cargo, rsync, OpenSSL, and validator shared libraries.
Example: python3 prepare_workspace.py /tmp/cat-run
Use --prepare-only to defer pip installation and Rust compilation.
"""
import argparse
import platform
from pathlib import Path
import shutil
import subprocess
import sys
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('workspace',type=Path)
ap.add_argument('--prepare-only',action='store_true')
a=ap.parse_args()
src=Path(__file__).resolve().parent
artifact=src.parents[1]
out=a.workspace.expanduser().resolve()
if out == artifact or artifact in out.parents:
    ap.error('workspace must be outside artifact')
if out.exists(): ap.error('workspace must not already exist')
if platform.system() != 'Linux' or platform.machine() not in ('x86_64','AMD64'):
    ap.error('bundled validators require Linux x86_64')
for name in ['fort','routinator','octorpki','rpki-client']:
    if not (artifact/'RP/instruct'/name).is_file(): ap.error('missing validator: '+name)
if not a.prepare_only:
    for name in ['cargo','rsync','openssl']:
        if not shutil.which(name): ap.error('missing executable: '+name)
out.mkdir(parents=True)
for name in ['harness','batch_mutator','vendor']:
    shutil.copytree(src/name,out/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc','target'))
(out/'rp_bins').mkdir()
for name in ['fort','routinator','octorpki','rpki-client']:
    dest=out/'rp_bins'/name
    shutil.copy2(artifact/'RP/instruct'/name,dest)
    dest.chmod(dest.stat().st_mode | 0o111)
shutil.copy2(src/'requirements.txt',out/'requirements.txt')
(out/'results').mkdir()
(out/'harness/rsyncd.exp.conf').write_text(
    f'pid file = {out}/rsyncd.pid\nlock file = {out}/rsyncd.lock\n'
    'port = 8730\naddress = 127.0.0.1\nuse chroot = no\nread only = yes\nlist = no\n'
    f'[myrpki]\npath = {out}/harness/mutation/out/my_repo\n')
if not a.prepare_only:
    subprocess.run([sys.executable,'-m','venv',str(out/'harness/.venv')],check=True)
    subprocess.run([str(out/'harness/.venv/bin/python'),'-m','pip','install','-r',str(out/'requirements.txt')],check=True)
    subprocess.run(['cargo','build','--release','--locked','--manifest-path',str(out/'batch_mutator/Cargo.toml')],check=True)
print('Prepared:',out)
print('Next: python3',src/'run_campaign.py',out,'--repos 1000')
