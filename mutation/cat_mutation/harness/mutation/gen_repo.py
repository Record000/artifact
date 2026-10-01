#!/usr/bin/env python3
"""Generation-only entry for one base repository.

Reuses the copied artifact pipeline (main.py in this directory) but stops
after building the signed repository + TAL: no validators are run here.
Run with cwd = exp_cureasn1/harness so that ./mutation/... paths resolve.

Usage: python3 mutation/gen_repo.py [--seed S] [--depth 2] [--branch 1]
"""
import argparse
import os
import random
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main as artifact_main  # noqa: E402  (copied pipeline; original untouched)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.backends import default_backend  # noqa: E402
from rpki.crl.crl import CRLConfig, CrlNumConfig  # noqa: E402
from rpki.cert.config import signatureAlgorithmConfig  # noqa: E402
from rpki.roa.roa import ROAConfig  # noqa: E402
from rpki.mft.mft import MFTConfig  # noqa: E402
from rpki.cert.CertParser import certParser, eeCertParser  # noqa: E402
import json  # noqa: E402


def copy_if_exists(src: str, dst: str):
    if os.path.exists(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)


def generate(seed: int, tree_depth: int, branch_factor: int, base_repo: str):
    random.seed(seed)
    tmp_config_dir = "./mutation/out/tmp_configs/"

    os.system(f"rm -rf {base_repo} {tmp_config_dir}")
    os.makedirs(os.path.join(base_repo, "ca_certificate"), exist_ok=True)
    os.makedirs(os.path.join(base_repo, "key"), exist_ok=True)
    os.makedirs(os.path.join(base_repo, "tal"), exist_ok=True)
    os.makedirs(tmp_config_dir, exist_ok=True)
    # EE-key material paths hardcoded by the rpki builders (original layout)
    os.makedirs("./my_repo/key", exist_ok=True)
    os.makedirs("./my_repo/ca_certificate", exist_ok=True)

    all_nodes, root_node = artifact_main.build_topology(
        depth=tree_depth,
        branching_factor=branch_factor,
        ta_template="./mutation/data/ca_certificate_mutate.json",
        sub_template="./mutation/data/ca_certificate/sub_ca_mutate.json",
        mft_template="./mutation/data/ca_certificate/manifest.json",
        roa_template="./mutation/data/ca_certificate/roa_mutate.json",
        tmp_dir=tmp_config_dir,
    )

    # Phase 1: CA certificates (signed, valid)
    for node in all_nodes:
        is_ta = (node.level == 0)
        if is_ta:
            node.physical_dir = base_repo
            node.cert_path = os.path.join(base_repo, "ca_certificate.cer")
        else:
            node.physical_dir = os.path.join(node.parent.physical_dir, node.name)
            node.cert_path = os.path.join(node.parent.physical_dir, f"{node.name}.cer")
        os.makedirs(node.physical_dir, exist_ok=True)
        node.priv_key_path = os.path.join(base_repo, "key", f"key_L{node.level}_{node.name}.pem")

        p_priv = None
        if node.parent:
            p_priv = serialization.load_pem_private_key(
                open(node.parent.priv_key_path, 'rb').read(), None, default_backend())

        ca_config = certParser(json_data=json.load(open(node.json_config_path, "r"))).parser_cacert()
        artifact_main.build_ca(
            issuer_private_key=p_priv, ca_path=node.cert_path,
            config=ca_config, key_export_path=node.priv_key_path, is_ta=is_ta)

    # Phase 2: CRL / manifest / ROA per node + TAL export
    for node in all_nodes:
        if node.level == 0:
            artifact_main.export_tal(node.cert_path, os.path.join(base_repo, "tal/ta.tal"))

        crl_path = os.path.join(node.physical_dir, "revoked.crl")
        crl_config = CRLConfig(
            version=1,
            signature=signatureAlgorithmConfig(oid='1.2.840.113549.1.1.11', parameters=None),
            issuer=node.name,
            this_update="20241125055723Z",
            next_update="20301125055723Z",
            crl_number=CrlNumConfig(0, False),
            aki_critical=False,
            revoked_certificates=None,
        )
        artifact_main.build_crl(issuer_private_key_path=node.priv_key_path,
                                config=crl_config, crl_path=crl_path)

        mft_files = [crl_path]
        for child in node.children:
            mft_files.append(child.cert_path)

        if not node.children:
            roa_path = os.path.join(node.physical_dir, "test_roa.roa")
            roa_ee_data = json.load(open(node.roa_ee_json, "r"))["content"]["certificates"][0]
            roa_config = ROAConfig()
            roa_config.ee_config = eeCertParser(json_data=roa_ee_data).parse_eecert()
            artifact_main.build_roa(issuer_private_key_path=node.priv_key_path,
                                    roa_config=roa_config, roa_path=roa_path)
            node.roa_path = roa_path
            node.roa_ee_key_path = os.path.join(base_repo, "key", f"roa_ee_{node.name}.pem")
            copy_if_exists("./my_repo/key/roa_ee_private_key.pem", node.roa_ee_key_path)
            mft_files.append(roa_path)

        mft_path = os.path.join(node.physical_dir, "manifest.mft")
        mft_config = MFTConfig()
        mft_config.file_names = mft_files
        mft_ee_data = json.load(open(node.mft_ee_json, "r"))["content"]["certificates"][0]
        mft_config.ee_config = eeCertParser(json_data=mft_ee_data).parse_eecert()
        artifact_main.build_mft(issuer_private_key_path=node.priv_key_path,
                                mft_config=mft_config, mft_path=mft_path)
        node.crl_path = crl_path
        node.mft_path = mft_path
        node.mft_ee_key_path = os.path.join(base_repo, "key", f"mft_ee_{node.name}.pem")
        copy_if_exists("./my_repo/key/mft_ee_private_key.pem", node.mft_ee_key_path)

    n_certs = sum(1 for n in all_nodes)
    # dump topology metadata so post-rebuild (manifests + TAL) can reuse it
    topo = [{
        "level": n.level,
        "name": n.name,
        "physical_dir": n.physical_dir,
        "cert_path": n.cert_path,
        "priv_key_path": n.priv_key_path,
        "crl_path": getattr(n, "crl_path", os.path.join(n.physical_dir, "revoked.crl")),
        "mft_path": getattr(n, "mft_path", os.path.join(n.physical_dir, "manifest.mft")),
        "roa_path": getattr(n, "roa_path", os.path.join(n.physical_dir, "test_roa.roa")) if not n.children else None,
        "mft_ee_key_path": getattr(n, "mft_ee_key_path", os.path.join(base_repo, "key", f"mft_ee_{n.name}.pem")),
        "roa_ee_key_path": getattr(n, "roa_ee_key_path", os.path.join(base_repo, "key", f"roa_ee_{n.name}.pem")) if not n.children else None,
        "mft_ee_json": n.mft_ee_json,
        "roa_ee_json": n.roa_ee_json,
        "children": [c.name for c in n.children],
    } for n in all_nodes]
    with open(os.path.join(base_repo, "topology.json"), "w") as f:
        json.dump(topo, f, indent=1)
    return {"nodes": n_certs, "tal": os.path.join(base_repo, "tal/ta.tal")}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--depth', type=int, default=2)
    p.add_argument('--branch', type=int, default=1)
    p.add_argument('--base-repo', type=str, default="./mutation/out/my_repo/")
    a = p.parse_args()
    info = generate(a.seed, a.depth, a.branch, a.base_repo)
    print(f"GEN_OK nodes={info['nodes']} tal={info['tal']}")
