import secrets
import string
import random
import json
import time
import os
import shutil
import copy

def generate_mutated_ca_name():
    length = random.randint(4, 12)
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def sync_ee_json(ee_cert, issuer, aki, crl_uri, signed_object_uri):
    ee_cert["issuer"]["common_name"] = issuer
    for ext in ee_cert["extensions"]:
        if ext["extn_id"] == "authority_key_identifier":
            ext["extn_value"]["key_identifier"] = aki
        elif ext["extn_id"] == "crl_distribution_points":
            ext["extn_value"][0]["distribution_point"] = [crl_uri]
        elif ext["extn_id"] == "subject_information_access":
            ext["extn_value"][0]["access_location"] = signed_object_uri

class MutationBenchmarker:
    def __init__(self, tmp_dir="./tmp_bench"):
        self.tmp_dir = tmp_dir
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)

        self.ca_tpl = {
            "subject": {"common_name": ""},
            "issuer": {"common_name": ""},
            "subject_public_key_info": {
                "algorithm": {"algorithm": "rsa", "parameters": None}
            },
            "extensions": [
                {"extn_id": "key_identifier", "extn_value": ""},
                {"extn_id": "authority_key_identifier", "extn_value": {"key_identifier": ""}},
                {"extn_id": "authority_information_access", "extn_value": [
                    {"access_method": "ca_issuers", "access_location": ""}
                ]},
                {"extn_id": "crl_distribution_points", "extn_value": [
                    {"distribution_point": [""]}
                ]},
            ]
        }

        self.ee_tpl = {
            "issuer": {"common_name": ""},
            "extensions": [
                {"extn_id": "authority_key_identifier", "extn_value": {"key_identifier": ""}},
                {"extn_id": "crl_distribution_points", "extn_value": [
                    {"distribution_point": [""]}
                ]},
                {"extn_id": "subject_information_access", "extn_value": [
                    {"access_location": ""}
                ]}
            ]
        }

    def mutate_node_logic(self, level, name, ski, p_name, p_ski, p_uri):
        is_ta = (level == 0)
        rsync_base = "rsync://localhost:8080/myrpki"
        this_uri = rsync_base if is_ta else f"{p_uri}/{name}"

        # ---------------- CA JSON ----------------
        ca = copy.deepcopy(self.ca_tpl)

        ca["subject"]["common_name"] = name
        ca["issuer"]["common_name"] = name if is_ta else p_name

        ca["subject_public_key_info"]["algorithm"]["parameters"] = None

        for ext in ca["extensions"]:
            eid = ext["extn_id"]

            if eid == "key_identifier":
                ext["extn_value"] = ski

            elif eid == "authority_key_identifier":
                ext["extn_value"]["key_identifier"] = ski if is_ta else p_ski

            elif eid == "authority_information_access" and not is_ta:
                parent_cert = (
                    f"{p_uri}/ca_certificate.cer"
                    if level == 1
                    else f"{p_uri}/sub_ca.cer"
                )
                ext["extn_value"][0]["access_location"] = parent_cert
                # duplication fuzz
                ext["extn_value"].append({
                    "access_method": "ca_issuers",
                    "access_location": parent_cert
                })

            elif eid == "crl_distribution_points":
                ext["extn_value"][0]["distribution_point"] = [
                    f"{this_uri}/revoked.crl"
                ]

        # ---------------- EE JSON ----------------
        ee = copy.deepcopy(self.ee_tpl)
        sync_ee_json(
            ee,
            name,
            ski,
            f"{this_uri}/revoked.crl",
            f"{this_uri}/manifest.mft"
        )
        out = {
            "tbs_certificate": ca,
            "content": {"certificates": [{"tbs_certificate": ee}]}
        }
        with open(os.path.join(self.tmp_dir, f"{name}.json"), "w") as f:
            json.dump(out, f)

        return this_uri

    def build_tree_recursive(self, level, max_depth, branch, p_name=None, p_ski=None, p_uri=None):
        if level >= max_depth:
            return 0

        count = 0
        for _ in range(branch):
            name = generate_mutated_ca_name()
            ski = secrets.token_hex(20)

            uri = self.mutate_node_logic(level, name, ski, p_name, p_ski, p_uri)
            count += 1
            count += self.build_tree_recursive(level + 1, max_depth, branch, name, ski, uri)

        return count

# ------------------------------------------------------------
# Test Runner
# ------------------------------------------------------------
def run_test(label, depth, branch):
    bench = MutationBenchmarker()
    start = time.time()
    total = bench.build_tree_recursive(0, depth, branch)
    dur = (time.time() - start) * 1000
    avg = dur / total if total else 0
    print(f"[{label}] Depth={depth}, Branch={branch} | Nodes={total} | Total={dur:.2f}ms | Avg={avg:.2f}ms")

if __name__ == "__main__":
    cases = [
        ("teny scale", 2, 1),
        ("modern scale", 3, 5),
        ("large scale", 4, 6),
        ("deep scale", 10, 1),
    ]

    for c in cases:
        run_test(*c)
