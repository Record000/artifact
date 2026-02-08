import secrets
import string
import random
import os
import time
import json
import shutil
from collections import defaultdict

class MutationMetrics:
    def __init__(self):
        self.field_stats = defaultdict(list)
        self.total_edges = 0

    def timed_update(self, field_name, func):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        self.field_stats[field_name].append(end - start)
        self.total_edges += 1

metrics = MutationMetrics()

def generate_mutated_ca_name():
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))

def sync_ee_json(path, issuer, aki, crl_uri, signed_object_uri, template_data):
    data = json.loads(json.dumps(template_data))
    ee = data["content"]["certificates"][0]["tbs_certificate"]

    metrics.timed_update(
        "EE.Issuer",
        lambda: ee["issuer"].__setitem__("common_name", issuer)
    )

    for ext in ee["extensions"]:
        if ext["extn_id"] == "authority_key_identifier":
            metrics.timed_update(
                "EE.AKI",
                lambda: ext["extn_value"].__setitem__("key_identifier", aki)
            )
        elif ext["extn_id"] == "crl_distribution_points":
            metrics.timed_update(
                "EE.CRLDP",
                lambda: ext["extn_value"][0].__setitem__("distribution_point", [crl_uri])
            )
        elif ext["extn_id"] == "subject_information_access":
            metrics.timed_update(
                "EE.SIA",
                lambda: ext["extn_value"][0].__setitem__("access_location", signed_object_uri)
            )

    with open(path, "w") as f:
        json.dump(data, f)


def mutate_node_recursive(depth, max_depth, branch, p_info, base_dir, templates):
    if depth >= max_depth:
        return

    is_ta = (p_info is None)

    name = generate_mutated_ca_name()
    ski = secrets.token_hex(20)
    base_uri = "rsync://localhost:8080/myrpki"
    this_uri = base_uri if is_ta else f"{p_info['uri']}/{name}"

    ca_data = json.loads(json.dumps(templates['ca']))
    tbs = ca_data["tbs_certificate"]

    metrics.timed_update(
        "CA.Subject",
        lambda: tbs["subject"].__setitem__("common_name", name)
    )
    metrics.timed_update(
        "CA.Issuer",
        lambda: tbs["issuer"].__setitem__("common_name", name if is_ta else p_info["name"])
    )

    metrics.timed_update(
        "CA.SPKI.Params",
        lambda: tbs["subject_public_key_info"]["algorithm"].__setitem__("parameters", None)
    )

    for ext in tbs["extensions"]:
        eid = ext["extn_id"]

        if eid == "key_identifier":
            metrics.timed_update(
                "CA.SKI",
                lambda: ext.__setitem__("extn_value", ski)
            )

        elif eid == "authority_key_identifier":
            metrics.timed_update(
                "CA.AKI",
                lambda: ext["extn_value"].__setitem__("key_identifier", ski if is_ta else p_info["ski"])
            )

        elif eid == "authority_information_access" and not is_ta:
            parent_cert = (
                f"{p_info['uri']}/ca_certificate.cer"
                if depth == 1
                else f"{p_info['uri']}/sub_ca.cer"
            )

            metrics.timed_update(
                "CA.AIA.Set",
                lambda: ext["extn_value"][0].__setitem__("access_location", parent_cert)
            )
            metrics.timed_update(
                "CA.AIA.Dup",
                lambda: ext["extn_value"].append({
                    "access_method": "ca_issuers",
                    "access_location": parent_cert
                })
            )

        elif eid == "subject_information_access":
            metrics.timed_update(
                "CA.SIA.Repo",
                lambda: ext["extn_value"][0].__setitem__("access_location", f"{this_uri}/")
            )

    node_dir = os.path.join(base_dir, name)
    os.makedirs(node_dir, exist_ok=True)
    with open(os.path.join(node_dir, "ca.json"), "w") as f:
        json.dump(ca_data, f)

    sync_ee_json(
        os.path.join(node_dir, "mft.json"),
        name,
        ski,
        f"{this_uri}/revoked.crl",
        f"{this_uri}/manifest.mft",
        templates["ee"]
    )

    if depth == max_depth - 1:
        for i in range(4):
            sync_ee_json(
                os.path.join(node_dir, f"roa_{i}.json"),
                name,
                ski,
                f"{this_uri}/revoked.crl",
                f"{this_uri}/roa.roa",
                templates["ee"]
            )

    new_p_info = {"name": name, "ski": ski, "uri": this_uri}
    for _ in range(branch):
        mutate_node_recursive(depth + 1, max_depth, branch, new_p_info, node_dir, templates)


if __name__ == "__main__":
    TEMPLATES = {
        "ca": {
            "tbs_certificate": {
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
                    {"extn_id": "subject_information_access", "extn_value": [
                        {"access_method": "ca_repository", "access_location": ""}
                    ]}
                ]
            }
        },
        "ee": {
            "content": {
                "certificates": [{
                    "tbs_certificate": {
                        "issuer": {"common_name": ""},
                        "extensions": [
                            {"extn_id": "authority_key_identifier", "extn_value": {"key_identifier": ""}},
                            {"extn_id": "crl_distribution_points", "extn_value": [{"distribution_point": [""]}]},
                            {"extn_id": "subject_information_access", "extn_value": [
                                {"access_method": "1.3.6.1.5.5.7.48.11", "access_location": ""}
                            ]}
                        ]
                    }
                }]
            }
        }
    }

    SCENARIOS = [
        ("teny scale", 2, 2),
        ("modern scale", 3, 4),
        ("large scale", 4, 5),
    ]

    ROOT = "./test_bench_repo"
    if os.path.exists(ROOT):
        shutil.rmtree(ROOT)
    os.makedirs(ROOT)

    print(f"{'setting':<10} | {'fixed edges':<12} | {'total time(ms)':<12} | {'average on every edge(μs)':<14}")
    print("-" * 60)

    for label, d, b in SCENARIOS:
        metrics.total_edges = 0
        metrics.field_stats.clear()

        start = time.perf_counter()
        mutate_node_recursive(0, d, b, None, ROOT, TEMPLATES)
        dur_ms = (time.perf_counter() - start) * 1000
        avg_us = (dur_ms * 1000) / metrics.total_edges

        print(f"{label:<10} | {metrics.total_edges:<12} | {dur_ms:<12.4f} | {avg_us:<14.4f}")

    print("\n========== Top 10 ==========")
    ranked = sorted(
        metrics.field_stats.items(),
        key=lambda x: sum(x[1]) / len(x[1]),
        reverse=True
    )
    for field, samples in ranked[:10]:
        print(f"{field:25s} {(sum(samples)/len(samples))*1e6:.4f} μs")
