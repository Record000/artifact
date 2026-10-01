#!/usr/bin/env python3
"""CAT-paper-style post-mutation repair for local RPKI fixtures.

Implemented repair mechanisms explicitly described in the paper (§4.1, §6.3):
  * label-driven locating of changed fields even after structural mutation;
  * taint/length-style parent length repair while preserving manipulated visual
    tags/lengths by replaying cure_asn1 visual_tag/visual_length at final encode;
  * intentional mutated nodes are never overwritten;
  * certificate/CRL/CMS signatures and object-internal hashes are recomputed;
  * manifest file hashes are recomputed from current repository bytes;
  * RRDP snapshot/delta hash attributes are recomputed when RRDP XML exists.

The preferred input is the cure_asn1 Tree JSON exported by batch_mutator
(--state-dir).  Without a tree snapshot, the script falls back to a minimal
certificate-only parser so old cert-only campaigns still run.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.backends import default_backend  # noqa: E402
from cryptography import x509  # noqa: E402

TAL_URI = "rsync://localhost:8730/myrpki/ca_certificate.cer"
SHA256_RSA_OID_DER = bytes.fromhex("06092A864886F70D01010B")
OID_SKI = bytes.fromhex("0603551D0E")
OID_AKI = bytes.fromhex("0603551D23")


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    width = max(1, (n.bit_length() + 7) // 8)
    return bytes([0x80 | width]) + n.to_bytes(width, "big")


def read_key(path: str):
    return serialization.load_pem_private_key(open(path, "rb").read(), None, default_backend())


# ---------------- legacy minimal DER tree, kept for old cert-only runs -------

class Node:
    __slots__ = ("tag", "content", "children")

    def __init__(self, tag, content, children):
        self.tag = tag
        self.content = content
        self.children = children


def parse_tlv(data: bytes, off: int = 0):
    start = off
    if off >= len(data):
        raise ValueError("eof")
    t0 = data[off]
    off += 1
    if t0 & 0x1F == 0x1F:
        while off < len(data) and data[off] & 0x80:
            off += 1
        off += 1
    ln = data[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0:
            raise ValueError("indefinite length")
        length = int.from_bytes(data[off:off+n], "big")
        off += n
    else:
        length = ln
    tag = data[start:off - 1] if not (ln & 0x80) else data[start:start + 1]
    content = data[off:off+length]
    if len(content) != length:
        raise ValueError("truncated")
    children = _parse_children(content) if (t0 & 0x20) else None
    return Node(tag, content, children), off + length


def _parse_children(content: bytes):
    out, off = [], 0
    while off < len(content):
        node, off = parse_tlv(content, off)
        out.append(node)
    return out


def ser_node(n: Node) -> bytes:
    content = b"".join(ser_node(c) for c in n.children) if n.children is not None else n.content
    # n.tag in this legacy node is the tag-only bytes only for old-created nodes;
    # for parsed nodes it can include header.  Use first byte to avoid stale len.
    tag = n.tag[:1]
    return tag + der_len(len(content)) + content


# ---------------- cure_asn1 Tree JSON adapter --------------------------------

@dataclass
class TreeState:
    path: str
    obj_type: str
    data: dict

    def __post_init__(self):
        self.tokens: Dict[int, dict] = {int(k): v for k, v in self.data.get("tokens", {}).items()}
        self.root_id = int(self.data.get("root_id", 0))
        self.mutated_ids = {int(m.get("node_id")) for m in self.data.get("mutations", []) if "node_id" in m}
        self.parent = {tid: int(t.get("parent", 0)) for tid, t in self.tokens.items()}
        self.children = {tid: [int(c) for c in t.get("children", [])] for tid, t in self.tokens.items()}
        self.label_index: Dict[str, List[int]] = {}
        for tid, tok in self.tokens.items():
            name = label_name(tok)
            if name:
                self.label_index.setdefault(name, []).append(tid)
        self.changed = False

    def ids(self, name: str) -> List[int]:
        return list(self.label_index.get(name, []))

    def first(self, *names: str) -> Optional[int]:
        for n in names:
            ids = self.ids(n)
            if ids:
                return ids[0]
        return None

    def token(self, tid: int) -> dict:
        return self.tokens[int(tid)]

    def descendants(self, tid: int) -> Iterable[int]:
        stack = [int(tid)]
        while stack:
            cur = stack.pop()
            yield cur
            stack.extend(self.children.get(cur, []))

    def ancestors(self, tid: int) -> Iterable[int]:
        cur = int(tid)
        seen = set()
        while cur in self.tokens and cur not in seen:
            seen.add(cur)
            yield cur
            if cur == self.root_id:
                break
            cur = self.parent.get(cur, self.root_id)

    def intentional(self, tid: Optional[int]) -> bool:
        if tid is None:
            return False
        # Preserve exactly the selected mutation target and its subtree.
        # A mutated ancestor (especially a Length/Tag mutation) is preserved by
        # visual_tag/visual_length during final encoding and should not by
        # itself block repair of a necessary child field.
        return bool(set(self.descendants(tid)) & self.mutated_ids)

    def content_bytes(self, tid: int, logical: bool = False) -> bytes:
        tok = self.token(tid)
        tag_kind = tok.get("tag")
        children = self.children.get(tid, [])
        data = bytes(tok.get("data", []))
        # Mirrors cure_asn1::Tree::encode_node_content.
        if tag_kind in ("Sequence", "TLV", "Integer"):
            return data + b"".join(self.encode_node(c, logical) for c in children)
        if tag_kind == "Set":
            return b"".join(self.encode_node(c, logical) for c in children)
        if tag_kind in ("OctetString", "BitString", "ObjectIdentifier", "Cont0", "IA5String"):
            if children:
                return self.encode_node(children[0], logical)
            return data
        if tag_kind == "Implicit":
            return b"".join(self.encode_node(c, logical) for c in children)
        if tag_kind == "Null":
            return data
        return data + b"".join(self.encode_node(c, logical) for c in children)

    def encode_node(self, tid: int, logical: bool = False) -> bytes:
        tok = self.token(tid)
        body = self.content_bytes(tid, logical)
        if logical:
            tag = bytes([int(tok.get("tag_u", (tok.get("visual_tag") or [0])[0]))])
            ln = len(body)
        else:
            tag = bytes(tok.get("visual_tag") or [tok.get("tag_u", 0)])
            ln = int(tok.get("visual_length", len(body)))
        return tag + der_len(ln) + body

    def encode(self, logical: bool = False) -> bytes:
        out = self.encode_node(self.root_id, logical)
        if not logical:
            min_size = self.data.get("additional_info", {}).get("min_size")
            if min_size:
                while len(out) < int(min_size[0]):
                    out += b"\x00"
        return out

    def fix_sizes(self, tid: Optional[int] = None) -> int:
        if tid is None:
            tid = self.root_id
        body_len = len(self.content_bytes(tid, logical=True))
        tok = self.token(tid)
        tok["length"] = body_len
        if not tok.get("manipulated_length", False):
            tok["visual_length"] = body_len
        for c in self.children.get(tid, []):
            self.fix_sizes(c)
        return body_len

    def set_primitive(self, tid: int, value: bytes, clear_children: bool = True):
        tok = self.token(tid)
        tok["data"] = list(value)
        if clear_children:
            tok["children"] = []
            self.children[tid] = []
        tok["tainted"] = True
        self.changed = True
        self.fix_sizes(self.root_id)

    def signed_attrs_as_set_der(self, tid: int) -> bytes:
        body = self.content_bytes(tid, logical=True)
        return b"\x31" + der_len(len(body)) + body


def label_name(tok: dict) -> Optional[str]:
    info = tok.get("info")
    if not info:
        return None
    name = info.get("name") if isinstance(info, dict) else None
    if isinstance(name, str):
        return name
    if isinstance(name, dict) and name:
        return next(iter(name.keys()))
    return None


def load_tree(state_dir: str, rel: str, obj_type: str) -> Optional[TreeState]:
    if not state_dir:
        return None
    p = os.path.join(state_dir, rel + ".tree.json")
    if not os.path.exists(p):
        return None
    return TreeState(p, obj_type, json.load(open(p)))


def write_tree_object(tree: TreeState, abs_path: str):
    tree.fix_sizes(tree.root_id)
    open(abs_path, "wb").write(tree.encode(logical=False))


# ---------------- label-driven object repairs --------------------------------

def spki_key_bytes(tree: TreeState) -> Optional[bytes]:
    kid = tree.first("CertFldSubjectPublicKeyInfoPublicKey")
    if kid is None:
        return None
    data = bytes(tree.token(kid).get("data", []))
    return data[1:] if data else b""


def cert_ski(tree: TreeState) -> Optional[bytes]:
    sid = tree.first("CertExtSkiKeyIdentifier")
    return bytes(tree.token(sid).get("data", [])) if sid is not None else None



def load_cert_ski_der(path: str) -> Optional[bytes]:
    try:
        cert = x509.load_der_x509_certificate(open(path, "rb").read(), default_backend())
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return ext.value.digest
    except Exception:
        return None

def repair_cert_tree(tree: TreeState, node_meta: dict, issuer_key_path: str, parent_ski: Optional[bytes], entry: dict):
    spki_id = tree.first("CertFldSubjectPublicKeyInfoPublicKey")
    ski_id = tree.first("CertExtSkiKeyIdentifier")
    aki_id = tree.first("CertExtAkiKeyIdentifier")
    sig_id = tree.first("CertificateSignature")
    sig_alg_id = tree.first("CertificateSignatureAlgorithm", "CertFldSignature")
    tbs_id = tree.first("Certificate")

    if spki_id is not None and ski_id is not None:
        if tree.intentional(ski_id):
            entry["skipped"].append("ski: intentional mutation")
        else:
            key_der = spki_key_bytes(tree)
            if key_der is not None:
                tree.set_primitive(ski_id, hashlib.sha1(key_der).digest())
                entry["repairs"].append("label:ski:=SHA1(SPKI.publicKey)")

    if parent_ski and aki_id is not None:
        if tree.intentional(aki_id):
            entry["skipped"].append("aki: intentional mutation")
        else:
            tree.set_primitive(aki_id, parent_ski)
            entry["repairs"].append("label:aki:=parentSKI")

    if tbs_id is None or sig_id is None:
        entry["skipped"].append("signature: labeled TBS/signature missing")
        return
    if tree.intentional(sig_id) or tree.intentional(sig_alg_id):
        entry["skipped"].append("signature: intentional mutation")
        return
    try:
        key = read_key(issuer_key_path)
        sig = key.sign(tree.encode_node(tbs_id, logical=True), padding.PKCS1v15(), hashes.SHA256())
        tree.set_primitive(sig_id, b"\x00" + sig)
        entry["repairs"].append("label:resign(TBS)")
    except Exception as ex:
        entry["skipped"].append(f"signature: key/sign failed: {type(ex).__name__}")


def repair_crl_tree(tree: TreeState, ca_key_path: str, ca_ski: Optional[bytes], entry: dict):
    aki_id = tree.first("CertExtAkiKeyIdentifier")
    if ca_ski and aki_id is not None and not tree.intentional(aki_id):
        tree.set_primitive(aki_id, ca_ski)
        entry["repairs"].append("crl:aki:=issuerSKI")
    elif aki_id is not None and tree.intentional(aki_id):
        entry["skipped"].append("crl:aki intentional mutation")

    tbs_id = tree.first("Certificate")
    sig_id = tree.first("CertificateSignature")
    sig_alg_id = tree.first("CertificateSignatureAlgorithm", "CertFldSignature")
    if tbs_id is None or sig_id is None:
        entry["skipped"].append("crl: labeled TBS/signature missing")
        return
    if tree.intentional(sig_id) or tree.intentional(sig_alg_id):
        entry["skipped"].append("crl: signature intentional mutation")
        return
    try:
        sig = read_key(ca_key_path).sign(tree.encode_node(tbs_id, logical=True), padding.PKCS1v15(), hashes.SHA256())
        tree.set_primitive(sig_id, b"\x00" + sig)
        entry["repairs"].append("crl:resign(TBSCertList)")
    except Exception as ex:
        entry["skipped"].append(f"crl: signature failed: {type(ex).__name__}")


def repair_manifest_hashes(tree: TreeState, manifest_path: str, entry: dict):
    file_ids = tree.ids("MftFile")
    hash_ids = tree.ids("MftHash")
    if not file_ids or not hash_ids:
        entry["skipped"].append("mft: file/hash labels missing")
        return
    base_dir = os.path.dirname(manifest_path)
    for i, fid in enumerate(file_ids):
        if i >= len(hash_ids):
            break
        hid = hash_ids[i]
        name = bytes(tree.token(fid).get("data", [])).decode("utf-8", errors="ignore")
        target = os.path.join(base_dir, name)
        if tree.intentional(hid):
            entry["skipped"].append(f"mft:{name}: hash intentional mutation")
            continue
        if not os.path.exists(target):
            entry["skipped"].append(f"mft:{name}: listed file missing")
            continue
        digest = hashlib.sha256(open(target, "rb").read()).digest()
        tree.set_primitive(hid, b"\x00" + digest)
        entry["repairs"].append(f"mft:{name}:hash:=SHA256(file)")


def repair_cms_tree(tree: TreeState, abs_path: str, ee_key_path: Optional[str], entry: dict, is_manifest: bool = False):
    if is_manifest:
        repair_manifest_hashes(tree, abs_path, entry)

    econtent_id = tree.first("EContentProfiled")
    digest_id = tree.first("SignerInfoSignedAttributeMessageDigestAttributeValue")
    attrs_id = tree.first("SignerInfoSignedAttributes")
    sig_id = tree.first("SignerInfoSignature")

    if econtent_id is not None and digest_id is not None:
        if tree.intentional(digest_id):
            entry["skipped"].append("cms: messageDigest intentional mutation")
        else:
            digest = hashlib.sha256(tree.encode_node(econtent_id, logical=True)).digest()
            tree.set_primitive(digest_id, digest)
            entry["repairs"].append("cms:messageDigest:=SHA256(eContent)")

    if attrs_id is None or sig_id is None:
        entry["skipped"].append("cms: signedAttrs/signature labels missing")
        return
    if tree.intentional(sig_id):
        entry["skipped"].append("cms: signature intentional mutation")
        return
    if not ee_key_path or not os.path.exists(ee_key_path):
        entry["skipped"].append("cms: EE private key missing")
        return
    try:
        sig = read_key(ee_key_path).sign(tree.signed_attrs_as_set_der(attrs_id), padding.PKCS1v15(), hashes.SHA256())
        tree.set_primitive(sig_id, sig)
        entry["repairs"].append("cms:resign(signedAttrs)")
    except Exception as ex:
        entry["skipped"].append(f"cms: signature failed: {type(ex).__name__}")


# ---------------- RRDP hash repair -------------------------------------------

def repair_rrdp_hashes(base_repo: str) -> dict:
    changed, skipped = [], []
    pat = re.compile(r'(<(?:snapshot|delta)\b[^>]*?)uri="([^"]+)"([^>]*?)hash="([0-9A-Fa-f]+)"')
    for root, _, files in os.walk(base_repo):
        for fn in files:
            if not fn.endswith(".xml"):
                continue
            p = os.path.join(root, fn)
            text = open(p, "r", errors="ignore").read()
            if "hash=" not in text or ("snapshot" not in text and "delta" not in text):
                continue

            def repl(m):
                before, uri, middle, old_hash = m.group(1), m.group(2), m.group(3), m.group(4)
                candidates = [
                    os.path.join(root, uri),
                    os.path.join(base_repo, uri),
                    os.path.join(base_repo, os.path.basename(uri)),
                ]
                target = next((c for c in candidates if os.path.exists(c)), None)
                if not target:
                    skipped.append(f"rrdp:{os.path.relpath(p, base_repo)}:{uri}:missing")
                    return m.group(0)
                new_hash = hashlib.sha256(open(target, "rb").read()).hexdigest()
                changed.append(f"rrdp:{os.path.relpath(p, base_repo)}:{uri}")
                return f'{before}uri="{uri}"{middle}hash="{new_hash}"'

            new_text = pat.sub(repl, text)
            if new_text != text:
                open(p, "w").write(new_text)
    return {"changed": changed, "skipped": skipped}


# ---------------- topology / orchestration -----------------------------------

def rel(base_repo: str, path: str) -> str:
    return os.path.relpath(path, base_repo).replace(os.sep, "/")


def enrich_topology(topo: list, base_repo: str):
    by_name = {n["name"]: n for n in topo}
    for n in topo:
        pd = n["physical_dir"]
        n.setdefault("crl_path", os.path.join(pd, "revoked.crl"))
        n.setdefault("mft_path", os.path.join(pd, "manifest.mft"))
        n.setdefault("roa_path", os.path.join(pd, "test_roa.roa"))
        n.setdefault("mft_ee_key_path", os.path.join(base_repo, "key", f"mft_ee_{n['name']}.pem"))
        n.setdefault("roa_ee_key_path", os.path.join(base_repo, "key", f"roa_ee_{n['name']}.pem"))
    return by_name


def repair(base_repo: str, pristine_dir: str, state_dir: str):
    topo_path = os.path.join(base_repo, "topology.json")
    topo = json.load(open(topo_path))
    by_name = enrich_topology(topo, base_repo)
    parent_of = {c: n["name"] for n in topo for c in n.get("children", [])}
    report = {}
    cert_trees: Dict[str, TreeState] = {}
    cert_ski_by_name: Dict[str, Optional[bytes]] = {}

    def entry_for(path: str):
        r = rel(base_repo, path)
        return report.setdefault(r, {"repairs": [], "skipped": [], "mutated_fields": [], "mode": "tree"})

    # Pass 1: load certificate trees and recompute SKI/AKI/signatures in topo order.
    for n in sorted(topo, key=lambda x: x.get("level", 0)):
        cert_path = n["cert_path"]
        r = rel(base_repo, cert_path)
        entry = entry_for(cert_path)
        tree = load_tree(state_dir, r, "cer")
        if tree is None:
            entry["mode"] = "legacy/no-state"
            entry["skipped"].append("label repair skipped: tree snapshot missing")
            cert_ski_by_name[n["name"]] = load_cert_ski_der(cert_path)
            continue
        cert_trees[n["name"]] = tree
        parent_ski = cert_ski_by_name.get(parent_of.get(n["name"]))
        issuer_key = n["priv_key_path"] if n.get("level", 0) == 0 else by_name[parent_of[n["name"]]]["priv_key_path"]
        repair_cert_tree(tree, n, issuer_key, parent_ski, entry)
        write_tree_object(tree, cert_path)
        cert_ski_by_name[n["name"]] = cert_ski(tree)

    # TAL re-export from repaired TA certificate snapshot.
    tal_note = "tal: kept-existing"
    ta = next((n for n in topo if n.get("level", 0) == 0), None)
    if ta and ta["name"] in cert_trees:
        spki_id = cert_trees[ta["name"]].first("CertFldSubjectPublicKeyInfo")
        if spki_id is not None:
            spki_der = cert_trees[ta["name"]].encode_node(spki_id, logical=True)
            os.makedirs(os.path.join(base_repo, "tal"), exist_ok=True)
            open(os.path.join(base_repo, "tal", "ta.tal"), "wb").write(TAL_URI.encode() + b"\n\n" + base64.b64encode(spki_der))
            tal_note = "tal: fresh(label-spki)"

    # Pass 2: CRL, ROA/ASPA/GBR and other non-manifest CMS before manifests.
    for n in topo:
        crl_path = n.get("crl_path")
        if crl_path and os.path.exists(crl_path):
            entry = entry_for(crl_path)
            tree = load_tree(state_dir, rel(base_repo, crl_path), "crl")
            if tree:
                repair_crl_tree(tree, n["priv_key_path"], cert_ski_by_name.get(n["name"]), entry)
                write_tree_object(tree, crl_path)
            else:
                entry["mode"] = "no-state"
                entry["skipped"].append("crl: tree snapshot missing")
        for obj_key, typ, key_key in (("roa_path", "roa", "roa_ee_key_path"), ("asa_path", "asa", "asa_ee_key_path"), ("gbr_path", "gbr", "gbr_ee_key_path")):
            obj_path = n.get(obj_key)
            if obj_path and os.path.exists(obj_path):
                entry = entry_for(obj_path)
                tree = load_tree(state_dir, rel(base_repo, obj_path), typ)
                if tree:
                    repair_cms_tree(tree, obj_path, n.get(key_key), entry, is_manifest=False)
                    write_tree_object(tree, obj_path)
                else:
                    entry["mode"] = "no-state"
                    entry["skipped"].append(f"{typ}: tree snapshot missing")

    # Pass 3: manifests last because they hash the just-repaired objects.
    for n in topo:
        mft_path = n.get("mft_path")
        if mft_path and os.path.exists(mft_path):
            entry = entry_for(mft_path)
            tree = load_tree(state_dir, rel(base_repo, mft_path), "mft")
            if tree:
                repair_cms_tree(tree, mft_path, n.get("mft_ee_key_path"), entry, is_manifest=True)
                write_tree_object(tree, mft_path)
            else:
                entry["mode"] = "rebuilt/no-state"
                entry["skipped"].append("mft: tree snapshot missing; delegated to post_rebuild")

    # Complete the paper's nesting rule for manifests not directly mutated by
    # cure_asn1.  post_rebuild skips manifests that have a tree snapshot, so it
    # does not erase deliberate structural mutations preserved above.
    try:
        import post_rebuild  # local module in harness/mutation
        rb = post_rebuild.rebuild(base_repo, state_dir)
        if rb.get("manifests", 0):
            report["__post_rebuild__"] = {
                "repairs": [f"rebuilt_unmutated_manifests={rb.get('manifests', 0)}"],
                "skipped": [],
                "mutated_fields": [],
                "mode": "post_rebuild",
            }
    except Exception as ex:
        report["__post_rebuild__"] = {
            "repairs": [],
            "skipped": [f"post_rebuild failed: {type(ex).__name__}: {ex}"],
            "mutated_fields": [],
            "mode": "post_rebuild",
        }

    rrdp = repair_rrdp_hashes(base_repo)
    if rrdp["changed"] or rrdp["skipped"]:
        report["__rrdp__"] = {"repairs": rrdp["changed"], "skipped": rrdp["skipped"], "mutated_fields": [], "mode": "xml"}

    n_rep = sum(len(v["repairs"]) for v in report.values())
    n_skip = sum(len(v["skipped"]) for v in report.values())
    return {"report": report, "repair_actions": n_rep, "skipped_actions": n_skip, "tal": tal_note, "state_dir": state_dir}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--base-repo', type=str, default="./mutation/out/my_repo/")
    p.add_argument('--pristine', type=str, default="./mutation/out/pristine/")
    p.add_argument('--state-dir', type=str, default="./mutation/out/repair_state/")
    p.add_argument('--report', type=str, default="")
    a = p.parse_args()
    try:
        res = repair(a.base_repo, a.pristine, a.state_dir)
        ok = True
    except Exception as ex:
        res = {"report": {}, "repair_actions": 0, "skipped_actions": 0,
               "tal": f"repair_aborted: {type(ex).__name__}: {ex}", "state_dir": a.state_dir}
        ok = False
    if a.report:
        json.dump(res, open(a.report, "w"), indent=1)
    print(f"REPAIR_DONE certs={len(res['report'])} repair_actions={res['repair_actions']} skipped={res['skipped_actions']} {res['tal']}")
    sys.exit(0 if ok else 2)
