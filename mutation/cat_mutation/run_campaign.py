#!/usr/bin/env python3
"""Run cert-only CAT mutation and write cat_mutation_stats.csv outside artifact.
Requires a prepared workspace. Owns an isolated rsync process; port 8730 must be free.
"""
import argparse
from pathlib import Path
import os
import socket
import subprocess
import time
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('workspace',type=Path)
ap.add_argument('--repos',type=int,default=1000)
ap.add_argument('--start',type=int,default=1)
a=ap.parse_args()
w=a.workspace.resolve(); h=w/'harness'; py=h/'.venv/bin/python'
if a.repos < 1 or a.start < 1: ap.error('repos and start must be positive')
if (w/'results/cat_mutation').exists(): ap.error('campaign already exists; use a new workspace')
for f in [py,h/'run_experiment.py',w/'batch_mutator/target/release/batch_mutator']:
    if not f.exists(): ap.error('missing prepared dependency: '+str(f))
with socket.socket() as sock:
    try: sock.bind(('127.0.0.1',8730))
    except OSError: ap.error('port 8730 occupied; leave the existing service untouched')
# Fail before generating data when a validator cannot start (e.g. missing shared libraries).
import runpy
commands=runpy.run_path(str(h/'run_experiment.py'))['VALIDATORS']
for name,cmd in commands.items():
    executable=cmd[0]
    probe=([executable,'--library-path',cmd[2],cmd[3],'--help'] if name=='Routinator' and os.environ.get('CAT_LOADER') else [executable,'--help'])
    env=os.environ.copy()
    if env.get('CAT_LIBRARY_PATH'): env['LD_LIBRARY_PATH']=env['CAT_LIBRARY_PATH']+':'+env.get('LD_LIBRARY_PATH','')
    r=subprocess.run(probe,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,timeout=20)
    text=r.stdout.decode(errors='replace')
    if r.returncode in (126,127) or 'error while loading shared libraries' in text or 'not found (required by' in text:
        ap.error(name+' runtime check failed: '+text)
(h/'mutation/out/my_repo').mkdir(parents=True,exist_ok=True)
daemon=subprocess.Popen(['rsync','--daemon','--no-detach','--config='+str(h/'rsyncd.exp.conf')])
try:
    time.sleep(0.5)
    if daemon.poll() is not None: raise RuntimeError('rsync failed to start')
    env=os.environ.copy(); env['PYTHONDONTWRITEBYTECODE']='1'
    subprocess.run([str(py),str(h/'run_experiment.py'),'--repos',str(a.repos),'--start',str(a.start),'--rounds','7','--ta-rounds','3','--include-ta','--types','cer','--repair','--post-rebuild','--tag','cat_mutation'],cwd=h,env=env,check=True)
    subprocess.run([str(py),str(h/'stage_stats.py'),str(w/'results/cat_mutation'),'--csv',str(w/'results/cat_mutation_stats.csv')],cwd=h,env=env,check=True)
finally:
    if daemon.poll() is None:
        daemon.terminate()
        try: daemon.wait(timeout=10)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
