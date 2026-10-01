#!/usr/bin/env python3
"""Post-mutation publication rebuild for the cure_asn1 nofix arm.

Mirrors test_noDep.py's implicit consistency guarantees (its build-time
mutation means manifests are constructed AFTER certs are mutated, and the
TAL is exported from the mutated TA cert):

  1. re-export the TAL from the (possibly mutated) TA certificate
  2. rebuild every manifest.mft from the current on-disk bytes of the
     objects it lists (hash consistency), signed with the CA key

NO dependency references are repaired (AKI/SKI/subject/AIA stay broken) —
that is the nofix condition.

Usage: python3 mutation/post_rebuild.py [--base-repo ./mutation/out/my_repo/] [--state-dir DIR]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main as artifact_main  # noqa: E402
from rpki.mft.mft import MFTConfig  # noqa: E402
from rpki.cert.CertParser import eeCertParser  # noqa: E402


def rel(base_repo: str, path: str) -> str:
    return os.path.relpath(path, base_repo).replace(os.sep, "/")


def rebuild(base_repo: str, state_dir: str = ""):
    topo_path = os.path.join(base_repo, "topology.json")
    with open(topo_path) as f:
        topo = json.load(f)
    by_name = {n["name"]: n for n in topo}

    rebuilt = []
    for n in topo:
        pd = n["physical_dir"]
        crl_path = os.path.join(pd, "revoked.crl")

        mft_files = [crl_path]
        for child_name in n["children"]:
            mft_files.append(by_name[child_name]["cert_path"])

        roa_path = os.path.join(pd, "test_roa.roa")
        if not n["children"]:
            mft_files.append(roa_path)

        mft_path = os.path.join(pd, "manifest.mft")
        # In repair campaigns fix_repair.py updates mutated manifests in-place
        # while preserving their intentional cure_asn1 structural mutations.
        # Rebuilding here would erase those mutations; only rebuild manifests
        # that were not selected by the mutator / have no tree snapshot.
        if state_dir and os.path.exists(os.path.join(state_dir, rel(base_repo, mft_path) + ".tree.json")):
            continue
        mft_config = MFTConfig()
        mft_config.file_names = mft_files
        mft_ee_data = json.load(open(n["mft_ee_json"], "r"))["content"]["certificates"][0]
        mft_config.ee_config = eeCertParser(json_data=mft_ee_data).parse_eecert()
        artifact_main.build_mft(
            issuer_private_key_path=n["priv_key_path"],
            mft_config=mft_config, mft_path=mft_path)
        rebuilt.append(mft_path)

    # TAL from the (possibly mutated) TA cert — best-effort: on strict-parse
    # failure keep whatever TAL fix_repair already wrote (lenient SPKI export)
    ta_cert = next(n["cert_path"] for n in topo if n["level"] == 0)
    tal_status = "fresh"
    try:
        artifact_main.export_tal(ta_cert, os.path.join(base_repo, "tal/ta.tal"))
    except Exception:
        tal_status = "kept-existing"
    return {"manifests": len(rebuilt), "tal": tal_status}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--base-repo', type=str, default="./mutation/out/my_repo/")
    p.add_argument('--state-dir', type=str, default="")
    a = p.parse_args()
    info = rebuild(a.base_repo, a.state_dir)
    print(f"REBUILD_OK manifests={info['manifests']} tal={info['tal']}")
