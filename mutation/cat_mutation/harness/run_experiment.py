#!/usr/bin/env python3
"""cure_asn1 vs. paper-mutator comparison experiment.

Per repository i:
  1. generate a fully valid base repository (mutation/gen_repo.py, seed=i)
  2. mutate it with the batch_mutator (cure_asn1)          [--no-mutate skips]
  3. clear validator caches
  4. run the four patched validators (artifact/RP/instruct, read-only use)
  5. parse "FUZZ_METRIC: STAGE_<n>_" markers from each validator's own output
  6. write results/repo_XXXXXX/result.json + raw logs

Run with cwd = exp_cureasn1/harness. rsync daemon (rsyncd.exp.conf) must be
running on 127.0.0.1:8730 (start_rsyncd.sh).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
RP = os.path.join(HARNESS, "..", "rp_bins")  # copies of artifact/RP/instruct (chmod +x)
BATCH_MUTATOR = os.path.join(HARNESS, "..", "batch_mutator", "target", "release", "batch_mutator")
RESULTS = os.path.join(HARNESS, "..", "results")
# Optional standalone loader for older Linux hosts; default uses system glibc.
LOADER = os.environ.get("CAT_LOADER", "")
LOADER_LIBS = os.environ.get("CAT_LOADER_LIBS", "")
ROUTINATOR_PREFIX = ([LOADER, "--library-path", LOADER_LIBS] if LOADER else [])

STAGE_RE = re.compile(r"FUZZ_METRIC: STAGE_(\d)_")

VALIDATORS = {
    "Routinator": ROUTINATOR_PREFIX + [
        f"{RP}/routinator", "-vvvv", "--no-rir-tals",
        "--extra-tals-dir", "./mutation/out/my_repo/tal",
        "-r", "./mutation/out/rp_cache/routinator_cache",
        "--allow-dubious-hosts", "--disable-rrdp", "vrps",
        "--format", "csv", "--output", "./mutation/out/routinator_output.csv",
    ],
    "Fort": [
        f"{RP}/fort", "--mode=standalone",
        "--tal=./mutation/out/my_repo/tal",
        "--local-repository=./mutation/out/rp_cache/fort_cache",
        "--http.enabled=false", "--maximum-certificate-depth=102",
        "--log.enabled=true", "--log.level=debug",
        "--validation-log.enabled=true", "--validation-log.level=debug",
    ],
    "Octorpki": [
        f"{RP}/octorpki", "-allow.root", "-mode", "oneoff",
        "-tal.root", "./mutation/out/my_repo/tal/ta.tal",
        "-tal.name", "rfuzz_root",
        "-cache", "./mutation/out/rp_cache/octorpki_cache",
        "-output.roa", "./mutation/out/octorpki_output.json",
        "-output.sign=false", "-rrdp=false", "-loglevel", "debug",
    ],
    "RPKI Client": [
        f"{RP}/rpki-client",
        "-t", "./mutation/out/my_repo/tal/ta.tal",
        "-d", "./mutation/out/rp_cache/rpki-client_cache",
        "-v", "./mutation/out/rp_cache/rpki-client_output",
    ],
}

RP_TIMEOUT = 120  # seconds per validator


def clear_caches():
    for d in [
        "./mutation/out/rp_cache/routinator_cache",
        "./mutation/out/rp_cache/fort_cache",
        "./mutation/out/rp_cache/octorpki_cache",
        "./mutation/out/rp_cache/rpki-client_cache",
        "./mutation/out/rp_cache/rpki-client_output",
        "./mutation/out/octorpki_output.json",
    ]:
        if os.path.exists(d):
            shutil.rmtree(d, ignore_errors=True) if os.path.isdir(d) else os.remove(d)
    os.makedirs("./mutation/out/rp_cache/rpki-client_cache", exist_ok=True)
    os.makedirs("./mutation/out/rp_cache/rpki-client_output", exist_ok=True)
    # OctoRPKI's single-file rsync fetch is broken (file lands inside a dir);
    # pre-populate its cache with the (already mutated) repo tree instead.
    octo_repo = "./mutation/out/rp_cache/octorpki_cache/localhost:8730/myrpki"
    os.makedirs(os.path.dirname(octo_repo), exist_ok=True)
    shutil.copytree("./mutation/out/my_repo", octo_repo,
                    ignore=shutil.ignore_patterns("key", "tal", "my_repo", "tmp_configs"))


def run(cmd, timeout):
    env = os.environ.copy()
    # validator runtime libs (same as artifact env_local.sh)
    libs = os.environ.get("CAT_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = libs + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=HARNESS, env=env)
        out = (p.stdout or b"") + b"\n" + (p.stderr or b"")
        return out.decode("utf-8", errors="replace"), p.returncode
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"") + b"\n" + (e.stderr or b""))
        return out.decode("utf-8", errors="replace") + "\n__TIMEOUT__", -1


def parse_stages(text):
    hits = [int(m.group(1)) for m in STAGE_RE.finditer(text)]
    per_stage = {s: hits.count(s) for s in range(1, 6)}
    return {"stage_hits": per_stage, "max_stage": max(hits) if hits else 0, "n_markers": len(hits)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", type=int, default=1000)
    ap.add_argument("--start", type=int, default=1, help="first repo id / seed (inclusive)")
    ap.add_argument("--rounds", type=int, default=1, help="cure_asn1 mutation rounds per object")
    ap.add_argument("--types", type=str, default="cer", help="object types to mutate, comma sep")
    ap.add_argument("--num-objects", type=str, default="all", help="'all' or K")
    ap.add_argument("--include-ta", action="store_true", help="also mutate the TAL-referenced TA cert")
    ap.add_argument("--ta-rounds", type=int, default=None, help="separate mutation rounds for the TA cert")
    ap.add_argument("--post-rebuild", action="store_true",
                    help="after mutation: re-export TAL from mutated TA + rebuild manifests "
                         "(hash consistency, no reference repair) — test_noDep-parity nofix arm")
    ap.add_argument("--repair", action="store_true",
                    help="CAT-style repair after mutation: cure_asn1 label snapshots + "
                         "intentional-mutation preservation + length/signature/hash repair "
                         "for cert/CRL/CMS/MFT and RRDP hash refresh")
    ap.add_argument("--no-mutate", action="store_true", help="skip mutation (valid-repo baseline)")
    ap.add_argument("--validators", type=str, default="all", help="comma list or 'all'")
    ap.add_argument("--tag", type=str, default="", help="subdirectory tag for this campaign")
    args = ap.parse_args()
    os.chdir(HARNESS)

    vnames = list(VALIDATORS) if args.validators == "all" else [v.strip() for v in args.validators.split(",")]
    out_root = os.path.join(RESULTS, args.tag) if args.tag else RESULTS
    os.makedirs(out_root, exist_ok=True)

    for i in range(args.start, args.start + args.repos):
        t0 = time.time()
        repo_dir = os.path.join(out_root, f"repo_{i:06d}")
        os.makedirs(repo_dir, exist_ok=True)
        for stale in ("gen.log", "mutate.log", "rebuild.log", "repair.log", "repair.json", "mutations.jsonl"):
            p = os.path.join(repo_dir, stale)
            if os.path.exists(p):
                os.remove(p)

        # combined retry loop: generation failure / batch_mutator panic
        # (cure_asn1 labeling bug) / strict-parse rejection in post-rebuild
        # all get a fresh seed and a full regenerate+mutate+rebuild pass
        gen_ok = False
        mut_ok = None       # None: --no-mutate; True/False otherwise
        rebuild_ok = None   # None: not requested
        repair_ok = None    # None: not requested
        mut_summary = {"skipped": True}
        gen_seed = i
        for attempt in range(6):
            gen_seed = i if attempt == 0 else i * 1000 + attempt
            out, rc = run([sys.executable, "mutation/gen_repo.py", "--seed", str(gen_seed)], 120)
            gen_ok = rc == 0 and "GEN_OK" in out
            with open(os.path.join(repo_dir, "gen.log"), "a") as f:
                f.write(f"--- attempt {attempt} seed={gen_seed} ok={gen_ok}\n{out}")
            if not gen_ok:
                continue

            if args.no_mutate:
                mut_ok = True
                break

            mut_cmd = [
                os.path.abspath(BATCH_MUTATOR), "mutate-repo", "./mutation/out/my_repo",
                "--rounds", str(args.rounds), "--types", args.types,
                "--num-objects", args.num_objects, "--seed", str(gen_seed),
                "--meta", os.path.abspath(os.path.join(repo_dir, "mutations.jsonl")),
            ]
            if args.repair:
                # pristine backups plus cure_asn1 tree snapshots power the repair stage
                shutil.rmtree("./mutation/out/pristine", ignore_errors=True)
                shutil.rmtree("./mutation/out/repair_state", ignore_errors=True)
                mut_cmd += ["--backup-dir", "./mutation/out/pristine",
                            "--state-dir", "./mutation/out/repair_state"]
            if args.include_ta:
                mut_cmd.append("--include-ta")
                if args.ta_rounds is not None:
                    mut_cmd += ["--ta-rounds", str(args.ta_rounds)]
            out, rc = run(mut_cmd, 120)
            mut_ok = rc == 0
            with open(os.path.join(repo_dir, "mutate.log"), "a") as f:
                f.write(f"--- attempt {attempt} rc={rc}\n{out}")
            mut_summary = {"rc": rc}
            for line in out.splitlines():
                if '"summary"' in line:
                    try:
                        mut_summary = json.loads(line.strip())["summary"]
                    except Exception:
                        pass
            if not mut_ok:
                continue  # mutator crashed (I/O level) -> regenerate

            break

        if not gen_ok or mut_ok is False:
            raise RuntimeError(f"Generation/mutator failed after retries; inspect {repo_dir}")

        # post-mutation steps run ONCE, best-effort, outcome recorded as data:
        # no outcome gating or resampling — repairs follow the paper's rules,
        # whatever the validators then decide is the measurement itself
        repair_ok = None
        if gen_ok and args.repair and not args.no_mutate:
            repair_report = os.path.abspath(os.path.join(repo_dir, "repair.json"))
            out, rc = run([sys.executable, "mutation/fix_repair.py",
                           "--state-dir", "./mutation/out/repair_state",
                           "--report", repair_report], 180)
            repair_ok = rc == 0
            try:
                rr = json.load(open(repair_report))
                repair_ok = repair_ok and not str(rr.get("tal", "")).startswith("repair_aborted")
            except Exception:
                repair_ok = False
            with open(os.path.join(repo_dir, "repair.log"), "w") as f:
                f.write(out)

        rebuild_ok = None
        if gen_ok and args.post_rebuild and not args.no_mutate:
            out, rc = run([sys.executable, "mutation/post_rebuild.py",
                           "--state-dir", "./mutation/out/repair_state"], 120)
            rebuild_ok = rc == 0 and "REBUILD_OK" in out
            with open(os.path.join(repo_dir, "rebuild.log"), "w") as f:
                f.write(out)

        # 3. clear caches, 4. run validators, 5. parse
        clear_caches()
        vres = {}
        for name in vnames:
            out, rc = run(VALIDATORS[name], RP_TIMEOUT)
            log_path = os.path.join(repo_dir, f"{name.replace(' ', '_')}.log")
            with open(log_path, "w") as f:
                f.write(out)
            vres[name] = {"rc": rc, **parse_stages(out)}

        # 6. result
        result = {
            "repo_id": i, "seed": i, "gen_ok": gen_ok, "gen_seed": gen_seed,
            "mutated": mut_ok is True or (mut_ok is None and gen_ok),
            "mut_ok": mut_ok, "mutation": mut_summary,
            "rebuild_ok": rebuild_ok, "repair_ok": repair_ok,
            "validators": vres, "elapsed_s": round(time.time() - t0, 1),
        }
        with open(os.path.join(repo_dir, "result.json"), "w") as f:
            json.dump(result, f, indent=2)
        summary = " ".join(f"{n}:max={vres[n]['max_stage']}" for n in vnames)
        print(f"[{i}] gen_ok={gen_ok} {summary} ({result['elapsed_s']}s)", flush=True)


if __name__ == "__main__":
    main()
