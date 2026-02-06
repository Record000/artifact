#!/usr/bin/env python3
"""
RPKI Certificate Repository Generator based on Context-Free Grammar (CFG)

This module implements a CFG-based RPKI repository generator as described in:
"POSTER: Fuzzing RPKI Validators with Semantic and Structural Awareness"

Grammar Definition G = (V, Σ, R, S):
    Non-terminals (V):
        [LC] - Logical CA: A logical CA node containing required files
        [Cs] - Child Set: Set of child CAs
        [Rs] - ROA Set: Set of ROA objects

    Terminals (Σ):
        [C] - CA Certificate (.cer)
        [M] - Manifest (.mft)
        [L] - CRL (.crl)
        [R] - ROA (.roa)

    Start Symbol: S

    Production Rules (R):
        S -> [LC]
        [LC] -> [C] [M] [Cs] [Rs] [L]
        [Cs] -> [LC] [Cs] | ε
        [Rs] -> [R] [Rs] | ε

Semantic Awareness:
    - Child CA certificates ([Cs]) are signed by the parent CA [LC]
    - Manifest ([M]) must contain hashes of all files in the CA's directory
    - CRL ([L]) must have correct AKI matching the CA's SKI
    - ROA ([R]) must be signed by the CA's EE key
"""

import os
import sys
import datetime
import hashlib
import base64
import argparse
import random
import shutil
from pathlib import Path

# Add parent directory to path to import rpki module
sys.path.insert(0, str(Path(__file__).parent))

from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

# Cryptography imports
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509 as crypto_x509

# RPKI-specific imports
from asn1crypto import x509, cms, core, algos, crl, keys
from rpki import certificate, manifest, roa


# ============================================================================
# Tree Structure Enumerations
# ============================================================================

class TreeShape:
    """Tree shape types - defines CA tree topology"""
    CHAIN = "chain"           # Chain: all nodes on a single path
    STAR = "star"             # Star: all nodes are direct children of root
    BALANCED = "balanced"     # Balanced: evenly distributed, like full binary tree
    SKEWED = "skewed"         # Skewed: 1-2 large branches, rest are small
    DIAMOND = "diamond"       # Diamond: wide in middle, narrow at both ends
    FUNNEL = "funnel"         # Funnel: wide at root, narrow at bottom
    SPINDLE = "spindle"       # Spindle: wide at both ends, narrow in middle
    RANDOM = "random"         # Completely random
    SPINE = "spine"           # Spine: main path + random side branches (original behavior)

    @classmethod
    def all_shapes(cls):
        return [cls.CHAIN, cls.STAR, cls.BALANCED, cls.SKEWED,
                cls.DIAMOND, cls.FUNNEL, cls.SPINDLE, cls.RANDOM, cls.SPINE]

    @classmethod
    def from_string(cls, value: str):
        shapes = {v: v for v in cls.all_shapes()}
        return shapes.get(value, cls.RANDOM)


class ROADistribution:
    """ROA distribution strategy in the tree"""
    ROOT_HEAVY = "root_heavy"     # Root-heavy: concentrated at shallow levels (70% ROA in top 30% depth)
    LEAF_HEAVY = "leaf_heavy"     # Leaf-heavy: concentrated at deep levels (70% ROA in bottom 30% depth)
    UNIFORM = "uniform"           # Uniform distribution
    PATH_CONCENTRATED = "path"    # Concentrated on a few paths
    SINGLE_PATH = "single_path"   # Only on a single path
    RANDOM = "random"             # Completely random

    @classmethod
    def all_distributions(cls):
        return [cls.ROOT_HEAVY, cls.LEAF_HEAVY, cls.UNIFORM,
                cls.PATH_CONCENTRATED, cls.SINGLE_PATH, cls.RANDOM]

    @classmethod
    def from_string(cls, value: str):
        dists = {v: v for v in cls.all_distributions()}
        return dists.get(value, cls.RANDOM)


# ============================================================================
# Configuration Classes
# ============================================================================

@dataclass
class GeneratorConfig:
    """Configuration for RPKI repository generation.
    
    Simplified Parameters:
    - Only 3 core structural parameters: depth, max_branch, min_branch
    - Only 3 tree types: full, random, sparse
    - No conflicting constraints (num_ca, leaf_count removed)
    """
    
    # Core structural parameters
    depth: int = 3              # Maximum depth of CA hierarchy
    max_branch: int = 2         # Maximum number of children per CA
    min_branch: int = 1         # Minimum number of children per CA (auto-clamped)
    
    # Tree structure type (simplified to 3 clear options)
    # - full: Every non-leaf node has exactly max_branch children
    # - random: Random [0, max_branch] children, may terminate early
    # - sparse: Random [min_branch, max_branch] children
    tree_type: str = "full"
    random_seed: Optional[int] = None  # Random seed for reproducibility
    
    # Quantity parameters
    num_roa: int = 1           # Number of ROAs per CA
    num_mft: int = 1           # Number of Manifests per CA
    num_crl: int = 1           # Number of CRLs per CA
    
    # Performance parameters
    reuse_keys: bool = True    # Reuse EE keys for performance (True=all objects share one key, "per_type"=manifest and ROAs use separate keys, False=each object has unique key)
    key_size: int = 2048       # RSA key size
    
    # Output parameters
    output_dir: str = "cfg_output"
    base_uri: str = "rsync://localhost:8730/repo"
    clean_output: bool = True  # Clean output directory before generation
    
    # AS and IP allocation
    base_as: int = 65000       # Starting AS number
    base_ip: Tuple[int, int, int] = (10, 0, 0)  # Starting IP prefix (10.0.0.0/24)
    
    def __post_init__(self):
        """Validate and fix configuration parameters."""
        # Auto-clamp min_branch to avoid errors
        if self.min_branch > self.max_branch:
            self.min_branch = self.max_branch
        
        if self.min_branch < 0:
            self.min_branch = 0
        
        if self.max_branch < 1:
            self.max_branch = 1
        
        if self.depth < 1:
            self.depth = 1
        
        # Validate tree_type
        valid_types = ["full", "random", "sparse", "skeleton"]
        if self.tree_type not in valid_types:
            print(f"Warning: Unknown tree_type '{self.tree_type}', defaulting to 'full'")
            self.tree_type = "full"



# ============================================================================
# Utility Functions
# ============================================================================

def generate_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate a new RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def get_spki_bytes(key) -> bytes:
    """Get SubjectPublicKeyInfo bytes from a key."""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def calculate_ski(key) -> bytes:
    """
    Calculate Subject Key Identifier (SKI) using RFC 5280 Method 1.
    
    SKI is the SHA-1 hash of the BIT STRING subjectPublicKey value.
    """
    spki_bytes = get_spki_bytes(key)
    spki = keys.PublicKeyInfo.load(spki_bytes)
    pubkey_bitstring = spki['public_key']
    pubkey_bytes = bytes(pubkey_bitstring)
    return hashlib.sha1(pubkey_bytes).digest()


def save_der(obj, path: str) -> None:
    """Save a DER-encoded object to a file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(obj.dump())


# ============================================================================
# Certificate Creation Functions
# ============================================================================

def create_basic_cert_extensions(
    subject_key,
    issuer_key,
    subject_name: str,
    issuer_name: str,
    serial: int,
    ski: bytes,
    aki: Optional[bytes] = None,
    is_ca: bool = True
) -> Tuple[List, x509.Time, x509.Time]:
    """Create basic certificate extensions and validity period."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_before = x509.Time({'utc_time': now - datetime.timedelta(hours=1)})
    not_after = x509.Time({'utc_time': now + datetime.timedelta(days=365)})
    
    extensions = []
    
    # Basic Constraints - ONLY for CA certificates
    # EE certificates (for Manifest/ROA signing) MUST NOT have this extension per RFC 6487
    if is_ca:
        bc_val = x509.BasicConstraints({'ca': True, 'path_len_constraint': None})
        extensions.append({
            'extn_id': '2.5.29.19',
            'critical': True,
            'extn_value': bc_val
        })
    
    # Certificate Policies (RFC 6484)
    # EE certificates MUST have this, CA certificates MUST have this
    cp_val = x509.CertificatePolicies([
        {'policy_identifier': '1.3.6.1.5.5.7.14.2'}
    ])
    extensions.append({
        'extn_id': '2.5.29.32',
        'critical': True,
        'extn_value': cp_val
    })
    
    # Key Usage - per RFC 6487
    # CA certificates: keyCertSign, cRLSign
    # EE certificates: digitalSignature
    if is_ca:
        ku = {'key_cert_sign', 'crl_sign'}
    else:
        ku = {'digital_signature'}
    ku_val = x509.KeyUsage(ku)
    extensions.append({
        'extn_id': '2.5.29.15',
        'critical': True,
        'extn_value': ku_val
    })
    
    # Subject Key Identifier
    ski_val = core.OctetString(ski)
    extensions.append({
        'extn_id': '2.5.29.14',
        'critical': False,
        'extn_value': ski_val
    })
    
    # Authority Key Identifier (if not root)
    if aki:
        aki_val = x509.AuthorityKeyIdentifier({'key_identifier': aki})
        extensions.append({
            'extn_id': '2.5.29.35',
            'critical': False,
            'extn_value': aki_val
        })
    
    return extensions, not_before, not_after


def sign_cert(tbs_cert, issuer_key) -> x509.Certificate:
    """Sign a TBS certificate with the issuer's private key."""
    tbs_bytes = tbs_cert.dump()
    signature = issuer_key.sign(
        tbs_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    cert = x509.Certificate({
        'tbs_certificate': tbs_cert,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature_value': signature
    })
    return cert


def create_root_ca_cert(key, sia_uri: str, name: str = "CN=Root") -> x509.Certificate:
    """
    Create a self-signed root CA certificate.
    
    Semantic: Root CA is the trust anchor, signed by itself.
    Contains full IP and AS resource blocks.
    """
    ski = calculate_ski(key)
    extensions, before, after = create_basic_cert_extensions(
        key, key, name, name, 1, ski, aki=None, is_ca=True
    )
    
    # Subject Info Access (SIA) - points to manifest and repository
    sia_val = x509.SubjectInfoAccessSyntax([
        {'access_method': 'id-ad-rpkiManifest', 
         'access_location': x509.GeneralName({'uniform_resource_identifier': f"{sia_uri}/manifest.mft"})},
        {'access_method': 'ca_repository', 
         'access_location': x509.GeneralName({'uniform_resource_identifier': f"{sia_uri}/"})}
    ])
    extensions.append({
        'extn_id': '1.3.6.1.5.5.7.1.11',
        'critical': False,
        'extn_value': sia_val
    })
    
    # IP Address Blocks (full IPv4 range)
    ipv4_prefix = certificate.IPAddress(tuple())
    ipv4_or_range = certificate.IPAddressOrRange({'addressPrefix': ipv4_prefix})
    ipv4_seq = certificate.IPAddressOrRangeSeq([ipv4_or_range])
    ipv4_choice = certificate.IPAddressChoice({'addressesOrRanges': ipv4_seq})
    ip_blocks = certificate.IPAddrBlocks([{'addressFamily': b'\x00\x01', 'ipAddressChoice': ipv4_choice}])
    extensions.append({
        'extn_id': '1.3.6.1.5.5.7.1.7',
        'critical': True,
        'extn_value': ip_blocks
    })
    
    # AS Identifier Blocks (full AS range)
    as_range = certificate.ASRange({'min': 0, 'max': 4294967295})
    as_or_range = certificate.ASIdOrRange({'range': as_range})
    as_seq = certificate.ASIdOrRangeSeq([as_or_range])
    as_choice = certificate.ASIdentifierChoice({'asIdsOrRanges': as_seq})
    as_ids = certificate.ASIdentifiers({'asnum': as_choice})
    extensions.append({
        'extn_id': '1.3.6.1.5.5.7.1.8',
        'critical': True,
        'extn_value': as_ids
    })
    
    tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': 1,
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': x509.Name.build({'common_name': 'Root'}),
        'validity': {'not_before': before, 'not_after': after},
        'subject': x509.Name.build({'common_name': 'Root'}),
        'subject_public_key_info': keys.PublicKeyInfo.load(get_spki_bytes(key)),
        'extensions': extensions
    })
    
    return sign_cert(tbs, key)


def create_child_ca_cert(
    parent_cert: x509.Certificate,
    parent_key,
    child_key,
    serial: int,
    child_name: str,
    sia_uri: str,
    aia_uri: str,
    crl_uri: str
) -> x509.Certificate:
    """
    Create a child CA certificate signed by the parent CA.
    
    Semantic Awareness:
    - The child CA certificate ([C]) is signed by the parent CA's private key
    - The AKI extension contains the parent's SKI, establishing the chain of trust
    - The SIA points to the child's manifest and repository
    - The AIA points to the parent's certificate for validation
    - IP and AS resources are inherited from parent (inherit extension)
    """
    child_ski = calculate_ski(child_key)
    
    # Extract parent's SKI for AKI
    parent_ski = None
    for ext in parent_cert['tbs_certificate']['extensions']:
        if ext['extn_id'].dotted == '2.5.29.14':
            parent_ski = ext['extn_value'].native
            break
    
    extensions, before, after = create_basic_cert_extensions(
        child_key, parent_key, child_name,
        parent_cert['tbs_certificate']['subject'].native,
        serial, child_ski, aki=parent_ski, is_ca=True
    )
    
    # Authority Info Access (AIA) - points to parent's certificate
    aia_val = x509.AuthorityInfoAccessSyntax([
        {'access_method': 'ca_issuers', 
         'access_location': x509.GeneralName({'uniform_resource_identifier': aia_uri})}
    ])
    extensions.append({
        'extn_id': '1.3.6.1.5.5.7.1.1',
        'critical': False,
        'extn_value': aia_val
    })
    
    # Subject Info Access (SIA) - points to child's manifest and repository
    sia_val = x509.SubjectInfoAccessSyntax([
        {'access_method': 'id-ad-rpkiManifest', 
         'access_location': x509.GeneralName({'uniform_resource_identifier': f"{sia_uri}/manifest.mft"})},
        {'access_method': 'ca_repository', 
         'access_location': x509.GeneralName({'uniform_resource_identifier': f"{sia_uri}/"})}
    ])
    extensions.append({
        'extn_id': '1.3.6.1.5.5.7.1.11',
        'critical': False,
        'extn_value': sia_val
    })
    
    # IP Address Blocks - inherit from parent
    ip_blocks = certificate.IPAddrBlocks([
        {'addressFamily': b'\x00\x01', 'ipAddressChoice': certificate.IPAddressChoice({'inherit': None})}
    ])
    extensions.append({
        'extn_id': '1.3.6.1.5.5.7.1.7',
        'critical': True,
        'extn_value': ip_blocks
    })
    
    # AS Identifier Blocks - inherit from parent
    as_ids = certificate.ASIdentifiers({
        'asnum': certificate.ASIdentifierChoice({'inherit': None})
    })
    extensions.append({
        'extn_id': '1.3.6.1.5.5.7.1.8',
        'critical': True,
        'extn_value': as_ids
    })
    
    # CRL Distribution Points
    dp_name = x509.DistributionPointName({
        'full_name': [x509.GeneralName({'uniform_resource_identifier': crl_uri})]
    })
    dp = x509.DistributionPoint({'distribution_point': dp_name})
    crl_dp = x509.CRLDistributionPoints([dp])
    extensions.append({
        'extn_id': '2.5.29.31',
        'critical': False,
        'extn_value': crl_dp
    })
    
    tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': serial,
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': parent_cert['tbs_certificate']['subject'],
        'validity': {'not_before': before, 'not_after': after},
        'subject': x509.Name.build({'common_name': child_name}),
        'subject_public_key_info': keys.PublicKeyInfo.load(get_spki_bytes(child_key)),
        'extensions': extensions
    })
    
    return sign_cert(tbs, parent_key)


def create_crl(
    issuer_cert: x509.Certificate,
    issuer_key,
    crl_number: int,
    serials_revoked: List[int] = None
) -> crl.CertificateList:
    """
    Create a Certificate Revocation List (CRL).
    
    Semantic Awareness:
    - The CRL ([L]) must have an AKI extension matching the issuer's SKI
    - This allows validators to verify which CA issued this CRL
    """
    if serials_revoked is None:
        serials_revoked = []
    
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    
    revoked_certs = []
    for s in serials_revoked:
        revoked_certs.append({
            'user_certificate': s,
            'revocation_date': now,
            'crl_entry_extensions': []
        })
    
    crl_data = {
        'version': 'v2',
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': issuer_cert['tbs_certificate']['subject'],
        'this_update': x509.Time({'utc_time': now}),
        'next_update': x509.Time({'utc_time': now + datetime.timedelta(days=365)}),
        'crl_extensions': [
            {
                'extn_id': '2.5.29.20',
                'critical': False,
                'extn_value': core.Integer(crl_number)
            }
        ]
    }
    
    if revoked_certs:
        crl_data['revoked_certificates'] = revoked_certs
    
    tbs_crl = crl.TbsCertList(crl_data)
    
    # Add AKI extension matching issuer's SKI
    ski_bytes = None
    for ext in issuer_cert['tbs_certificate']['extensions']:
        if ext['extn_id'].dotted == '2.5.29.14':
            ski_bytes = ext['extn_value'].native
            break
    
    if ski_bytes:
        aki_val = x509.AuthorityKeyIdentifier({'key_identifier': ski_bytes})
        tbs_crl['crl_extensions'].append({
            'extn_id': '2.5.29.35',
            'critical': False,
            'extn_value': aki_val
        })
    
    tbs_bytes = tbs_crl.dump()
    signature = issuer_key.sign(tbs_bytes, padding.PKCS1v15(), hashes.SHA256())
    
    cert_list = crl.CertificateList({
        'tbs_cert_list': tbs_crl,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': signature
    })
    
    return cert_list


def create_manifest(
    issuer_cert: x509.Certificate,
    issuer_key,
    file_mapping: List[Tuple[str, str]],
    manifest_number: int,
    output_path: str,
    crl_uri: str,
    aia_uri: str,
    ee_key=None
) -> None:
    """
    Create an RPKI Manifest file.
    
    Semantic Awareness:
    - The Manifest ([M]) must contain SHA-256 hashes of ALL files in the CA's directory:
      * The CA's own CRL ([L])
      * All ROA objects ([R]) issued by this CA
      * All child CA certificates ([C]) issued by this CA
    - This ensures integrity: any modification to files will be detected
    """
    # Build file list with hashes
    file_list = []
    for fname, fpath in file_mapping:
        with open(fpath, 'rb') as f:
            content = f.read()
        h = hashlib.sha256(content).digest()
        bits = []
        for byte in h:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        file_list.append({'file': fname, 'hash': core.BitString(tuple(bits))})
    
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    mft_content = manifest.RPKIManifest({
        'manifestNumber': manifest_number,
        'thisUpdate': now,
        'nextUpdate': now + datetime.timedelta(days=365),
        'fileHashAlg': algos.DigestAlgorithmId('sha256'),
        'fileList': file_list
    })
    
    mft_der = mft_content.dump()
    
    # Generate or reuse EE key
    if ee_key is None:
        ee_key = generate_key()
    ee_ski = calculate_ski(ee_key)
    
    # Get CA's SKI for AKI
    ca_ski = None
    for ext in issuer_cert['tbs_certificate']['extensions']:
        if ext['extn_id'].dotted == '2.5.29.14':
            ca_ski = ext['extn_value'].native
            break
    
    # Create EE certificate for manifest signing
    ee_name = f"CN=MFT-{manifest_number}"
    exts, bef, aft = create_basic_cert_extensions(
        ee_key, issuer_key, ee_name,
        issuer_cert['tbs_certificate']['subject'].native,
        manifest_number + 1000, ee_ski, ca_ski, is_ca=False
    )
    
    # Get CA repository URI from issuer cert
    ca_repo_uri = None
    for ext in issuer_cert['tbs_certificate']['extensions']:
        if ext['extn_id'].dotted == '1.3.6.1.5.5.7.1.11':
            for access in ext['extn_value'].native:
                if access['access_method'] == 'ca_repository':
                    ca_repo_uri = access['access_location']
                    break
    
    # Add SIA to EE cert
    if ca_repo_uri:
        fname = os.path.basename(output_path)
        full_uri = ca_repo_uri.rstrip('/') + "/" + fname
        sia_val = x509.SubjectInfoAccessSyntax([
            {'access_method': '1.3.6.1.5.5.7.48.11',
             'access_location': x509.GeneralName({'uniform_resource_identifier': full_uri})}
        ])
        exts.append({
            'extn_id': '1.3.6.1.5.5.7.1.11',
            'critical': False,
            'extn_value': sia_val
        })
    
    # Add IP and AS inherit extensions
    ip_blocks = certificate.IPAddrBlocks([
        {'addressFamily': b'\x00\x01', 'ipAddressChoice': certificate.IPAddressChoice({'inherit': None})}
    ])
    exts.append({
        'extn_id': '1.3.6.1.5.5.7.1.7',
        'critical': True,
        'extn_value': ip_blocks
    })
    
    as_ids = certificate.ASIdentifiers({'asnum': certificate.ASIdentifierChoice({'inherit': None})})
    exts.append({
        'extn_id': '1.3.6.1.5.5.7.1.8',
        'critical': True,
        'extn_value': as_ids
    })
    
    # Add AIA
    aia_val = x509.AuthorityInfoAccessSyntax([
        {'access_method': 'ca_issuers',
         'access_location': x509.GeneralName({'uniform_resource_identifier': aia_uri})}
    ])
    exts.append({
        'extn_id': '1.3.6.1.5.5.7.1.1',
        'critical': False,
        'extn_value': aia_val
    })
    
    # Add CRLDP - EE certificates MUST have this per RFC 6487
    dp_name = x509.DistributionPointName({
        'full_name': [x509.GeneralName({'uniform_resource_identifier': crl_uri})]
    })
    dp = x509.DistributionPoint({'distribution_point': dp_name})
    crl_dp = x509.CRLDistributionPoints([dp])
    exts.append({
        'extn_id': '2.5.29.31',
        'critical': False,
        'extn_value': crl_dp
    })
    
    # Create and sign EE certificate
    ee_tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': manifest_number + 1000,
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': issuer_cert['tbs_certificate']['subject'],
        'validity': {'not_before': bef, 'not_after': aft},
        'subject': x509.Name.build({'common_name': ee_name.replace("CN=", "")}),
        'subject_public_key_info': keys.PublicKeyInfo.load(get_spki_bytes(ee_key)),
        'extensions': exts
    })
    ee_cert = sign_cert(ee_tbs, issuer_key)
    
    # Sign the manifest
    digest_algo = {'algorithm': 'sha256'}
    sha256 = hashlib.sha256(mft_der).digest()
    
    signed_attrs = [
        {'type': 'content_type', 'values': ['rpkiManifest']},
        {'type': 'message_digest', 'values': [sha256]},
        {'type': 'signing_time', 'values': [cms.Time({'utc_time': now})]}
    ]
    
    sda_obj = cms.CMSAttributes(signed_attrs)
    to_sign = sda_obj.dump()
    sig_val = ee_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
    
    signer_info = {
        'version': 'v3',
        'sid': cms.SignerIdentifier({'subject_key_identifier': ee_ski}),
        'digest_algorithm': digest_algo,
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': sig_val
    }
    
    signed_data = {
        'version': 'v3',
        'digest_algorithms': [digest_algo],
        'encap_content_info': {
            'content_type': 'rpkiManifest',
            'content': mft_content
        },
        'certificates': [ee_cert],
        'signer_infos': [signer_info]
    }
    
    content_info = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data
    })
    
    save_der(content_info, output_path)


def create_roa(
    issuer_cert: x509.Certificate,
    issuer_key,
    roa_number: int,
    output_name: str,
    crl_uri: str,
    aia_uri: str,
    as_id: int,
    ip_prefix: Tuple[int, int, int],
    ee_key=None,
    serial: Optional[int] = None
) -> cms.ContentInfo:
    """
    Create a Route Origin Authorization (ROA).
    
    Semantic Awareness:
    - The ROA ([R]) is signed by the CA's EE key
    - Authorizes a specific AS to announce a specific IP prefix
    - The EE certificate must have correct SIA pointing to the ROA file
    """
    if ee_key is None:
        ee_key = generate_key()
    ee_ski = calculate_ski(ee_key)
    
    # Get CA's SKI for AKI
    ca_ski = None
    for ext in issuer_cert['tbs_certificate']['extensions']:
        if ext['extn_id'].dotted == '2.5.29.14':
            ca_ski = ext['extn_value'].native
            break
    
    # Create EE certificate for ROA signing
    ee_name = f"CN=ROA-{roa_number}"
    exts, bef, aft = create_basic_cert_extensions(
        ee_key, issuer_key, ee_name,
        issuer_cert['tbs_certificate']['subject'].native,
        serial if serial is not None else roa_number + 2000,
        ee_ski, ca_ski, is_ca=False
    )
    
    # Get CA repository URI
    ca_repo_uri = None
    for ext in issuer_cert['tbs_certificate']['extensions']:
        if ext['extn_id'].dotted == '1.3.6.1.5.5.7.1.11':
            for access in ext['extn_value'].native:
                if access['access_method'] == 'ca_repository':
                    ca_repo_uri = access['access_location']
                    break
    
    # Add SIA to EE cert
    if ca_repo_uri:
        full_uri = ca_repo_uri.rstrip('/') + "/" + output_name
        sia_val = x509.SubjectInfoAccessSyntax([
            {'access_method': '1.3.6.1.5.5.7.48.11',
             'access_location': x509.GeneralName({'uniform_resource_identifier': full_uri})}
        ])
        exts.append({
            'extn_id': '1.3.6.1.5.5.7.1.11',
            'critical': False,
            'extn_value': sia_val
        })
    
    # Add AIA
    aia_val = x509.AuthorityInfoAccessSyntax([
        {'access_method': 'ca_issuers',
         'access_location': x509.GeneralName({'uniform_resource_identifier': aia_uri})}
    ])
    exts.append({
        'extn_id': '1.3.6.1.5.5.7.1.1',
        'critical': False,
        'extn_value': aia_val
    })
    
    # Add IP extension (empty for ROA EE cert)
    ipv4_prefix = certificate.IPAddress(tuple())
    ipv4_or_range = certificate.IPAddressOrRange({'addressPrefix': ipv4_prefix})
    ipv4_seq = certificate.IPAddressOrRangeSeq([ipv4_or_range])
    ipv4_choice = certificate.IPAddressChoice({'addressesOrRanges': ipv4_seq})
    ip_blocks = certificate.IPAddrBlocks([{'addressFamily': b'\x00\x01', 'ipAddressChoice': ipv4_choice}])
    exts.append({
        'extn_id': '1.3.6.1.5.5.7.1.7',
        'critical': True,
        'extn_value': ip_blocks
    })
    
    # Add CRLDP - EE certificates MUST have this per RFC 6487
    dp_name = x509.DistributionPointName({
        'full_name': [x509.GeneralName({'uniform_resource_identifier': crl_uri})]
    })
    dp = x509.DistributionPoint({'distribution_point': dp_name})
    crl_dp = x509.CRLDistributionPoints([dp])
    exts.append({
        'extn_id': '2.5.29.31',
        'critical': False,
        'extn_value': crl_dp
    })
    
    # Create and sign EE certificate
    ee_tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': serial if serial is not None else roa_number + 2000,
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': issuer_cert['tbs_certificate']['subject'],
        'validity': {'not_before': bef, 'not_after': aft},
        'subject': x509.Name.build({'common_name': ee_name.replace("CN=", "")}),
        'subject_public_key_info': keys.PublicKeyInfo.load(get_spki_bytes(ee_key)),
        'extensions': exts
    })
    ee_cert = sign_cert(ee_tbs, issuer_key)
    
    # Build ROA content
    ip_bytes = bytes(ip_prefix)
    bits = []
    for byte in ip_bytes:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    ipv4_prefix = tuple(bits)
    
    roa_ip = roa.ROAIPAddress({
        'address': ipv4_prefix,
        'maxLength': 24
    })
    
    roa_family = roa.ROAIPAddressFamily({
        'addressFamily': b'\x00\x01',
        'addresses': [roa_ip]
    })
    
    roa_content = roa.RouteOriginAttestation({
        'version': 0,
        'asID': as_id,
        'ipAddrBlocks': [roa_family]
    })
    
    roa_der = roa_content.dump()
    
    # Sign the ROA
    digest_algo = {'algorithm': 'sha256'}
    sha256 = hashlib.sha256(roa_der).digest()
    
    signed_attrs = [
        {'type': 'content_type', 'values': ['routeOriginAuthz']},
        {'type': 'message_digest', 'values': [sha256]},
        {'type': 'signing_time', 'values': [cms.Time({'utc_time': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)})]}
    ]
    
    sda_obj = cms.CMSAttributes(signed_attrs)
    to_sign = sda_obj.dump()
    sig_val = ee_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
    
    signer_info = {
        'version': 'v3',
        'sid': cms.SignerIdentifier({'subject_key_identifier': ee_ski}),
        'digest_algorithm': digest_algo,
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': sig_val
    }
    
    signed_data = {
        'version': 'v3',
        'digest_algorithms': [digest_algo],
        'encap_content_info': {
            'content_type': 'routeOriginAuthz',
            'content': roa_content
        },
        'certificates': [ee_cert],
        'signer_infos': [signer_info]
    }
    
    content_info = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data
    })
    
    return content_info


# ============================================================================
# CFG Non-terminal Classes
# ============================================================================

class ROASet:
    """
    Represents the [Rs] non-terminal in the CFG.
    
    Production Rule: [Rs] -> [R] [Rs] | ε
    
    This class manages the generation of ROA objects for a CA.
    Each ROA ([R]) authorizes a specific AS to announce a specific IP prefix.
    """
    
    def __init__(self, config: GeneratorConfig, parent_ca: 'LogicalCA'):
        self.config = config
        self.parent_ca = parent_ca
        self.roas: List[Dict] = []  # List of ROA metadata
        self._generated = False
    
    def generate(self) -> List[Tuple[str, str]]:
        """
        Generate ROA objects.
        
        Returns:
            List of (filename, filepath) tuples for generated ROAs.
        """
        if self._generated:
            return [(r['name'], r['path']) for r in self.roas]
        
        self._generated = True
        result = []
        
        # Generate num_roa ROAs
        for i in range(self.config.num_roa):
            roa_name = f"roa_{i}.roa"
            roa_path = os.path.join(self.parent_ca.directory, roa_name)
            
            # Allocate unique AS ID and IP prefix
            as_id = self.config.base_as + self.parent_ca.global_serial
            ip_third = (self.parent_ca.global_serial // 256) % 256
            ip_fourth = self.parent_ca.global_serial % 256
            ip_prefix = (self.config.base_ip[0], ip_third, ip_fourth)
            
            # Create ROA
            roa_obj = create_roa(
                self.parent_ca.cert,
                self.parent_ca.key,
                self.parent_ca.global_serial,
                roa_name,
                self.parent_ca.crl_uri,
                self.parent_ca.aia_uri,
                as_id=as_id,
                ip_prefix=ip_prefix,
                ee_key=self.parent_ca.get_ee_key(object_type="roa"),
                serial=self.parent_ca.global_serial
            )
            
            save_der(roa_obj, roa_path)
            
            self.roas.append({
                'name': roa_name,
                'path': roa_path,
                'as_id': as_id,
                'ip_prefix': ip_prefix
            })
            
            result.append((roa_name, roa_path))
            self.parent_ca.global_serial += 1
        
        return result
    
    def count(self) -> int:
        """Return the number of ROAs in this set."""
        return len(self.roas)


class ChildSet:
    """
    Represents the [Cs] non-terminal in the CFG.
    
    Production Rule: [Cs] -> [LC] [Cs] | ε
    
    This class manages the recursive generation of child CAs.
    Each child CA ([LC]) is a complete CA node with its own certificate,
    manifest, CRL, and potentially more children and ROAs.
    
    Semantic Awareness:
    - Child CA certificates are signed by the parent CA
    - This establishes the chain of trust from root to leaf
    
    Tree Structure Types:
    - full: Every non-leaf node has exactly max_branch children
    - non_full: Non-leaf nodes have random children between min_branch and max_branch
    - complete: All levels except last are filled; last level is left-aligned
    - non_complete: Similar to non_full but leaves not necessarily left-aligned
    - random: Random branching, may have early termination (0 children possible)
    """
    
    def __init__(self, config: GeneratorConfig, parent_ca: 'LogicalCA'):
        self.config = config
        self.parent_ca = parent_ca
        self.children: List['LogicalCA'] = []
        self._generated = False
        self._child_index = 0  # Track position for complete tree generation
    
    def _calculate_num_children(self) -> int:
        """
        Calculate number of children based on tree type configuration.
        
        Simplified to 3 tree types:
        - full: max_branch children (deterministic)
        - random: [0, max_branch] children (may terminate early)
        - sparse: [min_branch, max_branch] children (never 0)
        
        Returns:
            Number of children to generate for this node.
        """
        tree_type = self.config.tree_type
        max_b = self.config.max_branch
        min_b = self.config.min_branch
        depth = self.parent_ca.depth
        max_depth = self.config.depth
        
        # Check depth limit - always stop at max depth
        if depth >= max_depth:
            return 0
        
        if tree_type == "full":
            # Full tree: every internal node has exactly max_branch children
            return max_b
        
        elif tree_type == "random":
            # Random tree: [0, max_branch] children, may terminate early
            # Root always has at least 1 child to avoid empty tree
            if depth == 0:
                return random.randint(1, max_b)
            return random.randint(0, max_b)
        
        elif tree_type == "sparse":
            # Sparse tree: [min_branch, max_branch] children
            # Root always has at least 1 child to avoid empty tree
            if depth == 0 and min_b == 0:
                return random.randint(1, max_b)
            return random.randint(min_b, max_b)
        
        elif tree_type == "skeleton":
            # Skeleton tree: sparse tree with guaranteed path to max depth
            # and wide branching at the deepest level.
            # Ideal for testing extreme depth/width without exponential blowup.
            #
            # Structure:
            #   - Main spine: always 1 child to ensure reaching max depth
            #   - Intermediate levels: 1 + random(0-1) with 30% chance
            #   - Deepest level (depth = max-1): expand to max_branch children
            #
            # This creates ~50-200 CAs even for depth=20, branch=10
            
            if depth == max_depth - 1:
                # At the level just before max depth, expand wide
                # This tests the extreme width at the deepest position
                return max_b
            elif depth == 0:
                # Root: always 1 main spine child
                # Plus optional extra branch with 30% chance
                return 1 + (1 if random.random() < 0.3 else 0)
            else:
                # Intermediate levels: main spine + occasional branches
                # 30% chance to add an extra branch
                return 1 + (1 if random.random() < 0.3 else 0)
        
        # Default to full tree behavior
        return max_b
    
    def generate(self) -> List[Tuple[str, str]]:
        """
        Generate child CAs recursively.
        
        Simplified: Only depth controls tree generation.
        No more num_ca or leaf_count constraints.
        
        Returns:
            List of (filename, filepath) tuples for child CA certificates.
        """
        if self._generated:
            return [(c.cert_name, c.cert_path) for c in self.children]
        
        self._generated = True
        result = []
        
        # Simple depth check - only constraint now
        if self.parent_ca.depth >= self.config.depth:
            return result
        
        # Determine number of children based on tree type
        num_children = self._calculate_num_children()
        
        for i in range(num_children):
            # Create child CA
            child_name = f"CA{self.parent_ca.global_serial}"
            child_dir = os.path.join(self.parent_ca.directory, child_name)
            child_uri = f"{self.parent_ca.sia_uri}/{child_name}"
            
            # Calculate URIs for child
            child_crl_uri = f"{child_uri}/revoked.crl"
            child_aia_uri = f"{self.parent_ca.sia_uri}/{child_name}.cer"
            
            # Generate child CA certificate
            child_key = generate_key(self.config.key_size)
            child_cert = create_child_ca_cert(
                self.parent_ca.cert,
                self.parent_ca.key,
                child_key,
                self.parent_ca.global_serial,
                child_name,
                child_uri,
                child_aia_uri,
                self.parent_ca.crl_uri
            )
            
            # Save child CA certificate in parent's directory
            child_cert_name = f"{child_name}.cer"
            child_cert_path = os.path.join(self.parent_ca.directory, child_cert_name)
            save_der(child_cert, child_cert_path)
            
            # Create LogicalCA for child
            child_ca = LogicalCA(
                config=self.config,
                name=child_name,
                cert=child_cert,
                key=child_key,
                directory=child_dir,
                sia_uri=child_uri,
                crl_uri=child_crl_uri,
                aia_uri=child_aia_uri,
                depth=self.parent_ca.depth + 1,
                parent=self.parent_ca,
                global_serial=self.parent_ca.global_serial + 1,
                ca_count=self.parent_ca.ca_count + 1
            )
            
            # Generate child CA content
            child_ca.generate()
            
            # Update parent counters with child's results
            self.parent_ca.global_serial = child_ca.global_serial
            self.parent_ca.ca_count = child_ca.ca_count
            
            self.children.append(child_ca)
            result.append((child_cert_name, child_cert_path))
        
        return result
    
    def count(self) -> int:
        """Return the number of child CAs."""
        return len(self.children)
    
    def get_all_descendants(self) -> List['LogicalCA']:
        """Get all descendant CAs recursively."""
        result = []
        for child in self.children:
            result.append(child)
            result.extend(child.child_set.get_all_descendants())
        return result


class LogicalCA:
    """
    Represents the [LC] non-terminal in the CFG.
    
    Production Rule: [LC] -> [C] [M] [Cs] [Rs] [L]
    
    This is the core class representing a complete CA node in the RPKI hierarchy.
    A LogicalCA contains:
    - [C]: CA Certificate
    - [M]: Manifest
    - [Cs]: Child Set (recursive)
    - [Rs]: ROA Set
    - [L]: CRL
    
    Semantic Awareness:
    - The CA certificate ([C]) is signed by the parent CA (or self for root)
    - The Manifest ([M]) contains hashes of all files in this CA's directory
    - The CRL ([L]) has AKI matching this CA's SKI
    - Child CAs ([Cs]) have certificates signed by this CA
    - ROAs ([Rs]) are signed by this CA's EE key
    """
    
    def __init__(
        self,
        config: GeneratorConfig,
        name: str,
        cert: x509.Certificate,
        key,
        directory: str,
        sia_uri: str,
        crl_uri: str,
        aia_uri: str,
        depth: int = 0,
        parent: Optional['LogicalCA'] = None,
        global_serial: int = 2,
        ca_count: int = 1
    ):
        self.config = config
        self.name = name
        self.cert = cert
        self.key = key
        self.directory = directory
        self.sia_uri = sia_uri
        self.crl_uri = crl_uri
        self.aia_uri = aia_uri
        self.depth = depth
        self.parent = parent
        self.global_serial = global_serial
        self.ca_count = ca_count
        
        # Terminal objects
        self.cert_name = f"{name}.cer"
        self.cert_path = os.path.join(directory, self.cert_name)
        
        # Non-terminal components
        self.child_set = ChildSet(config, self)
        self.roa_set = ROASet(config, self)
        
        # Generated files tracking
        self.generated_files: List[Tuple[str, str]] = []
        self.crl_files: List[Tuple[str, str]] = []
        self.mft_files: List[Tuple[str, str]] = []

        # EE key reuse - support three modes:
        # - True: all objects share one EE key (fastest, but OctoRPKI incompatible)
        # - "per_type": manifest and ROAs use separate EE keys (OctoRPKI compatible)
        # - False: each object has unique EE key (slowest, most flexible)
        self._shared_ee_key = None
        self._manifest_ee_key = None
        self._roa_ee_key = None

        if config.reuse_keys is True:
            # All objects share one EE key
            self._shared_ee_key = generate_key(config.key_size)
        elif config.reuse_keys == "per_type":
            # Manifest and ROAs use separate EE keys
            self._manifest_ee_key = generate_key(config.key_size)
            self._roa_ee_key = generate_key(config.key_size)
        # reuse_keys=False: each object generates its own key

        self._generated = False

    def get_ee_key(self, object_type: str = "default"):
        """
        Get EE key based on reuse configuration.

        Args:
            object_type: Type of object ("manifest", "roa", or "default")

        Returns:
            EE key to use for signing the object
        """
        if self.config.reuse_keys is True:
            # All objects share one EE key
            return self._shared_ee_key
        elif self.config.reuse_keys == "per_type":
            # Manifest and ROAs use separate EE keys (OctoRPKI compatible)
            if object_type == "manifest":
                return self._manifest_ee_key
            elif object_type == "roa":
                return self._roa_ee_key
            else:
                return generate_key(self.config.key_size)
        else:
            # reuse_keys=False: each object has unique EE key
            return generate_key(self.config.key_size)
    
    def generate_crls(self) -> List[Tuple[str, str]]:
        """
        Generate CRL objects ([L]).
        
        Semantic Awareness:
        - Each CRL must have AKI matching this CA's SKI
        - This allows validators to verify which CA issued the CRL
        - Only one CRL file is created per CA directory (revoked.crl)
        """
        result = []
        
        # Only create one CRL file per CA directory
        crl_name = "revoked.crl"
        crl_path = os.path.join(self.directory, crl_name)
        crl_obj = create_crl(self.cert, self.key, 1)
        save_der(crl_obj, crl_path)
        
        self.crl_files.append((crl_name, crl_path))
        result.append((crl_name, crl_path))
        
        return result
    
    def generate_manifests(self, file_mapping: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """
        Generate Manifest objects ([M]).
        
        Semantic Awareness:
        - The Manifest must contain SHA-256 hashes of ALL files in this CA's directory:
          * CRL files ([L])
          * ROA files ([R])
          * Child CA certificates ([C])
        - This ensures integrity: any modification will be detected
        - Only one Manifest file is created per CA directory (manifest.mft)
        """
        result = []
        
        # Only create one Manifest file per CA directory
        mft_name = "manifest.mft"
        mft_path = os.path.join(self.directory, mft_name)
        create_manifest(
            self.cert,
            self.key,
            file_mapping,
            1,
            mft_path,
            self.crl_uri,
            self.aia_uri,
            ee_key=self.get_ee_key(object_type="manifest")
        )
        
        self.mft_files.append((mft_name, mft_path))
        result.append((mft_name, mft_path))
        
        return result
    
    def generate(self) -> None:
        """
        Generate the complete CA node according to the production rule:
        [LC] -> [C] [M] [Cs] [Rs] [L]
        
        Generation order (following the production rule):
        1. [C] - CA Certificate (already created)
        2. [Cs] - Child Set (generate child CAs first)
        3. [Rs] - ROA Set (generate ROAs)
        4. [L] - CRL (generate CRLs)
        5. [M] - Manifest (generate last, includes all files)
        """
        if self._generated:
            return
        
        self._generated = True
        
        # Create directory
        os.makedirs(self.directory, exist_ok=True)
        
        # Collect all files for manifest
        all_files = []
        
        # [Cs] - Generate child CAs first
        # Semantic: Child CA certificates are signed by this CA
        child_certs = self.child_set.generate()
        all_files.extend(child_certs)
        
        # [Rs] - Generate ROAs
        roa_files = self.roa_set.generate()
        all_files.extend(roa_files)
        
        # [L] - Generate CRLs
        crl_files = self.generate_crls()
        all_files.extend(crl_files)
        
        # [M] - Generate Manifests (must include all files)
        # Semantic: Manifest contains hashes of all files in this CA's directory
        self.generate_manifests(all_files)
        
        # Track generated files
        self.generated_files = all_files

    def generate_content_only(self, child_cert_files: List[Tuple[str, str]] = None) -> None:
        """
        Generate only ROAs, CRL, and manifest for this CA.
        Does NOT generate child CAs.

        This is used when the CA hierarchy has been pre-built
        and we only need to generate the content (ROAs, CRL, manifest).

        Args:
            child_cert_files: List of (filename, filepath) for child CA certificates
                             to include in the manifest.
        """
        if self._generated:
            return

        self._generated = True
        os.makedirs(self.directory, exist_ok=True)

        # Collect all files for manifest
        all_files = []

        # Add child CA certificates (if any)
        if child_cert_files:
            all_files.extend(child_cert_files)

        # [Rs] - Generate ROAs
        roa_files = self.roa_set.generate()
        all_files.extend(roa_files)

        # [L] - Generate CRLs
        crl_files = self.generate_crls()
        all_files.extend(crl_files)

        # [M] - Generate Manifests (must include all files)
        self.generate_manifests(all_files)

        # Track generated files
        self.generated_files = all_files

    def is_leaf(self) -> bool:
        """Check if this CA is a leaf (no children)."""
        return len(self.child_set.children) == 0
    
    def get_stats(self) -> Dict:
        """Get statistics for this CA and its descendants."""
        stats = {
            'name': self.name,
            'depth': self.depth,
            'is_leaf': self.is_leaf(),
            'num_children': self.child_set.count(),
            'num_roas': self.roa_set.count(),
            'num_crls': len(self.crl_files),
            'num_mfts': len(self.mft_files),
            'children_stats': []
        }
        
        for child in self.child_set.children:
            stats['children_stats'].append(child.get_stats())
        
        return stats


# ============================================================================
# Main Generator Class
# ============================================================================

class RPKICFGGenerator:
    """
    Main RPKI repository generator based on CFG.

    Implements the grammar:
        S -> [LC]
        [LC] -> [C] [M] [Cs] [Rs] [L]
        [Cs] -> [LC] [Cs] | ε
        [Rs] -> [R] [Rs] | ε
    """

    def __init__(self, config: GeneratorConfig):
        self.config = config
        self.root_ca: Optional[LogicalCA] = None
        self.tal_path: Optional[str] = None
        # Track actual counts when using generate_with_limits
        self._actual_ca_count: Optional[int] = None
        self._actual_roa_count: Optional[int] = None
        self._actual_max_depth: Optional[int] = None
    
    def generate(self) -> LogicalCA:
        """
        Generate the complete RPKI repository.
        
        Returns:
            The root LogicalCA node.
        """
        # Initialize random seed for reproducibility (if specified)
        if self.config.random_seed is not None:
            random.seed(self.config.random_seed)
        
        # Setup output directories
        cache_root = os.path.join(self.config.output_dir, "cache")
        host_dir = os.path.join(cache_root, "localhost")
        repo_dir = os.path.join(host_dir, "repo")
        
        # Clean output directory if requested (default: True)
        # This ensures old files from previous runs don't mix with new files
        if self.config.clean_output and os.path.exists(repo_dir):
            # Robust cleanup with retry logic for file locking issues
            import time
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    shutil.rmtree(repo_dir)
                    break
                except PermissionError as e:
                    if attempt < max_retries - 1:
                        print(f"Warning: Permission error cleaning directory (attempt {attempt+1}), retrying...")
                        time.sleep(0.5)
                    else:
                        raise RuntimeError(f"Failed to clean output directory after {max_retries} attempts: {e}")
                except OSError as e:
                    if attempt < max_retries - 1:
                        print(f"Warning: OS error cleaning directory (attempt {attempt+1}), retrying...")
                        time.sleep(0.5)
                    else:
                        raise RuntimeError(f"Failed to clean output directory after {max_retries} attempts: {e}")
        
        os.makedirs(repo_dir, exist_ok=True)
        
        # Generate Root CA
        root_key = generate_key(self.config.key_size)
        root_cert = create_root_ca_cert(root_key, self.config.base_uri)
        
        # Save root certificate
        root_cer_name = "root.cer"
        root_cer_path = os.path.join(repo_dir, root_cer_name)
        save_der(root_cert, root_cer_path)
        
        # Generate TAL
        spki = get_spki_bytes(root_key)
        b64_key = base64.b64encode(spki).decode('ascii')
        tal_content = f"{self.config.base_uri}/{root_cer_name}\n\n{b64_key}"
        self.tal_path = os.path.join(self.config.output_dir, "rpki.tal")
        with open(self.tal_path, "w") as f:
            f.write(tal_content)
        
        # Create root LogicalCA
        root_crl_uri = f"{self.config.base_uri}/revoked.crl"
        root_aia_uri = f"{self.config.base_uri}/{root_cer_name}"
        
        self.root_ca = LogicalCA(
            config=self.config,
            name="Root",
            cert=root_cert,
            key=root_key,
            directory=repo_dir,
            sia_uri=self.config.base_uri,
            crl_uri=root_crl_uri,
            aia_uri=root_aia_uri,
            depth=0,
            parent=None,
            global_serial=2,
            ca_count=1
        )
        
        # Generate root CA content
        self.root_ca.generate()
        
        return self.root_ca
    
    def get_stats(self) -> Dict:
        """Get repository statistics."""
        if self.root_ca is None:
            return {}

        # If generate_with_limits was used, return the tracked counts
        if self._actual_ca_count is not None:
            return {
                'total_ca': self._actual_ca_count + 1,  # +1 for root
                'total_roa': self._actual_roa_count,
                'total_crl': self._actual_ca_count + 1,  # One CRL per CA
                'total_mft': self._actual_ca_count + 1,  # One manifest per CA
                'leaf_ca': self._actual_ca_count,  # All non-root CAs are leaves in this mode
                'max_depth': self._actual_max_depth if self._actual_max_depth is not None else 0
            }

        def count_nodes(ca: LogicalCA) -> Dict:
            stats = {
                'total_ca': 1,
                'total_roa': ca.roa_set.count(),
                'total_crl': len(ca.crl_files),
                'total_mft': len(ca.mft_files),
                'leaf_ca': 1 if ca.is_leaf() else 0,
                'max_depth': ca.depth
            }

            for child in ca.child_set.children:
                child_stats = count_nodes(child)
                stats['total_ca'] += child_stats['total_ca']
                stats['total_roa'] += child_stats['total_roa']
                stats['total_crl'] += child_stats['total_crl']
                stats['total_mft'] += child_stats['total_mft']
                stats['leaf_ca'] += child_stats['leaf_ca']
                stats['max_depth'] = max(stats['max_depth'], child_stats['max_depth'])

            return stats

        return count_nodes(self.root_ca)

    def generate_with_limits(
        self,
        target_ca_count: int,
        target_roa_count: int,
        max_depth: int = 10
    ) -> LogicalCA:
        """
        Generate RPKI repository with exact CA and ROA counts.

        This method creates a repository with precisely:
        - target_ca_count total CA nodes (excluding root)
        - target_roa_count total ROA nodes
        - Maximum depth of max_depth

        The CA tree structure is determined to fit within these constraints:
        - Branching is random but respects depth limit
        - ROA distribution is random across CAs

        Args:
            target_ca_count: Target total number of CA nodes (excluding root)
            target_roa_count: Target total number of ROA nodes
            max_depth: Maximum depth of CA hierarchy

        Returns:
            The root LogicalCA node.
        """
        # Initialize random seed for reproducibility (if specified)
        if self.config.random_seed is not None:
            random.seed(self.config.random_seed)

        # Setup output directories
        cache_root = os.path.join(self.config.output_dir, "cache")
        host_dir = os.path.join(cache_root, "localhost")
        repo_dir = os.path.join(host_dir, "repo")

        # Clean output directory
        if self.config.clean_output and os.path.exists(repo_dir):
            import time
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    shutil.rmtree(repo_dir)
                    break
                except (PermissionError, OSError) as e:
                    if attempt < max_retries - 1:
                        time.sleep(0.5)
                    else:
                        raise

        os.makedirs(repo_dir, exist_ok=True)

        # Generate Root CA
        root_key = generate_key(self.config.key_size)
        root_cert = create_root_ca_cert(root_key, self.config.base_uri)

        # Save root certificate
        root_cer_name = "root.cer"
        root_cer_path = os.path.join(repo_dir, root_cer_name)
        save_der(root_cert, root_cer_path)

        # Generate TAL
        spki = get_spki_bytes(root_key)
        b64_key = base64.b64encode(spki).decode('ascii')
        tal_content = f"{self.config.base_uri}/{root_cer_name}\n\n{b64_key}"
        self.tal_path = os.path.join(self.config.output_dir, "rpki.tal")
        with open(self.tal_path, "w") as f:
            f.write(tal_content)

        root_crl_uri = f"{self.config.base_uri}/revoked.crl"
        root_aia_uri = f"{self.config.base_uri}/{root_cer_name}"

        # Edge case: no CAs to create
        if target_ca_count == 0:
            root_logical_ca = LogicalCA(
                config=self.config,
                name="Root",
                cert=root_cert,
                key=root_key,
                directory=repo_dir,
                sia_uri=self.config.base_uri,
                crl_uri=root_crl_uri,
                aia_uri=root_aia_uri,
                depth=0,
                parent=None,
                global_serial=2,
                ca_count=1
            )
            # Generate root manifest
            root_logical_ca._generated = False
            root_logical_ca.generate()
            self.root_ca = root_logical_ca
            return self.root_ca

        # Build parent relationships for the CA tree
        # parent[i] = index of parent for CA i (0 = root)
        # CAs are numbered 1 to target_ca_count
        parent = [0] * (target_ca_count + 1)  # parent[0] unused, root is parent 0
        depth = [0] * (target_ca_count + 1)

        # Ensure we create a spine to max_depth first
        # This guarantees at least one path reaches exactly max_depth
        spine_length = min(target_ca_count, max_depth)
        for i in range(1, spine_length + 1):
            parent[i] = i - 1  # Each CA is child of previous CA (or root for i=1)
            depth[i] = i  # Depth equals index for the spine

        # Distribute remaining CAs randomly across eligible parents
        for i in range(spine_length + 1, target_ca_count + 1):
            # Find all eligible parents (CAs with depth < max_depth)
            eligible_parents = []
            for j in range(i):
                if j == 0:
                    d = 0
                else:
                    d = depth[j]
                # Can only be parent if this won't exceed max_depth
                if d < max_depth:
                    eligible_parents.append(j)

            # Random parent from eligible
            p = random.choice(eligible_parents) if eligible_parents else 0
            parent[i] = p
            depth[i] = (0 if p == 0 else depth[p]) + 1

        # Distribute ROAs randomly across CAs
        roa_allocation = [0] * (target_ca_count + 1)  # roa_allocation[i] = ROAs for CA i
        remaining_roas = target_roa_count

        # First, give at least 1 ROA to some CAs to distribute
        ca_indices = list(range(1, target_ca_count + 1))
        random.shuffle(ca_indices)

        for i in ca_indices:
            if remaining_roas <= 0:
                break
            # Give 1 to this CA
            roa_allocation[i] = 1
            remaining_roas -= 1

        # Distribute remaining ROAs randomly
        for _ in range(remaining_roas):
            i = random.randint(1, target_ca_count)
            roa_allocation[i] += 1

        # Track CAs and their data: index -> (dir, crl_uri, aia_uri, cert, key, cert_filename, cert_path)
        ca_data = {
            0: (repo_dir, root_crl_uri, root_aia_uri, root_cert, root_key, "root.cer", root_cer_path)
        }

        # Generate each CA sequentially
        for i in range(1, target_ca_count + 1):
            p = parent[i]
            parent_dir, parent_crl_uri, parent_aia_uri, parent_cert, parent_key, _, _ = ca_data[p]

            child_name = f"CA{i}"
            child_dir = os.path.join(parent_dir, child_name)
            os.makedirs(child_dir, exist_ok=True)

            # Build URIs
            # For root's direct children, use base_uri directly
            # For other CAs, use parent's directory path (removing the .cer file)
            if p == 0:  # Parent is root
                parent_base_uri = self.config.base_uri
            else:
                # Remove only the filename, keep the directory path
                parent_base_uri = parent_aia_uri.rsplit('.', 1)[0]

            child_uri = f"{parent_base_uri}/{child_name}"
            child_crl_uri = f"{child_uri}/revoked.crl"
            child_aia_uri = f"{parent_base_uri}/{child_name}.cer"

            # Generate child CA certificate
            child_key = generate_key(self.config.key_size)
            child_cert = create_child_ca_cert(
                parent_cert, parent_key,
                child_key, i + 1, child_name,
                child_uri, child_aia_uri, parent_crl_uri
            )

            # Save child CA certificate in parent's directory
            child_cert_path = os.path.join(parent_dir, f"{child_name}.cer")
            save_der(child_cert, child_cert_path)

            # Store for children to use: (dir, crl_uri, aia_uri, cert, key, cert_filename, cert_path)
            ca_data[i] = (child_dir, child_crl_uri, child_aia_uri, child_cert, child_key, f"{child_name}.cer", child_cert_path)

        # Build child-to-parent mapping for manifest generation
        # children_of[p] = list of child indices that have p as parent
        children_of = {i: [] for i in range(target_ca_count + 1)}
        for i in range(1, target_ca_count + 1):
            p = parent[i]
            children_of[p].append(i)

        # Store LogicalCA objects for later root assignment
        logical_cas = {}

        # Generate content from leaves up (reverse order helps ensure children are processed first)
        for i in range(target_ca_count, 0, -1):
            ca_dir, ca_crl_uri, ca_aia_uri, ca_cert, ca_key, ca_cert_name, ca_cert_path = ca_data[i]
            num_roas = roa_allocation[i]
            ca_name = f"CA{i}"

            # Collect child certificate files for this CA's manifest
            child_cert_files = []
            for child_idx in children_of[i]:
                _, _, _, _, _, child_cert_name, child_cert_path = ca_data[child_idx]
                child_cert_files.append((child_cert_name, child_cert_path))

            # Create LogicalCA
            logical_ca = LogicalCA(
                config=GeneratorConfig(
                    depth=0,
                    max_branch=0,
                    min_branch=0,
                    tree_type="full",
                    random_seed=self.config.random_seed,
                    num_roa=num_roas,
                    reuse_keys=self.config.reuse_keys,
                    key_size=self.config.key_size,
                    output_dir=self.config.output_dir,
                    base_uri=self.config.base_uri,
                    clean_output=False
                ),
                name=ca_name,
                cert=ca_cert,
                key=ca_key,
                directory=ca_dir,
                sia_uri=ca_aia_uri.rsplit('/', 1)[0] if '/' in ca_aia_uri else self.config.base_uri,
                crl_uri=ca_crl_uri,
                aia_uri=ca_aia_uri,
                depth=depth[i],
                parent=None,
                global_serial=2 + i * 100,
                ca_count=i + 1
            )

            # Generate only content (ROAs, CRL, manifest) - no children
            logical_ca.generate_content_only(child_cert_files)
            logical_cas[i] = logical_ca

        # Generate root content last
        # Collect child certificate files for root
        root_child_cert_files = []
        for child_idx in children_of[0]:
            _, _, _, _, _, child_cert_name, child_cert_path = ca_data[child_idx]
            root_child_cert_files.append((child_cert_name, child_cert_path))

        # Create root config with num_roa=0 (ROAs are only on child CAs)
        root_config = GeneratorConfig(
            depth=0,
            max_branch=0,
            min_branch=0,
            tree_type="full",
            random_seed=self.config.random_seed,
            num_roa=0,  # Root has no ROAs
            reuse_keys=self.config.reuse_keys,
            key_size=self.config.key_size,
            output_dir=self.config.output_dir,
            base_uri=self.config.base_uri,
            clean_output=False
        )

        root_logical_ca = LogicalCA(
            config=root_config,
            name="Root",
            cert=root_cert,
            key=root_key,
            directory=repo_dir,
            sia_uri=self.config.base_uri,
            crl_uri=root_crl_uri,
            aia_uri=root_aia_uri,
            depth=0,
            parent=None,
            global_serial=2,
            ca_count=target_ca_count + 1
        )
        root_logical_ca.generate_content_only(root_child_cert_files)

        # Track actual counts for get_stats()
        self._actual_ca_count = target_ca_count
        self._actual_roa_count = target_roa_count
        self._actual_max_depth = max(depth) if depth else 0

        self.root_ca = root_logical_ca
        return self.root_ca


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for the CFG-based RPKI generator."""
    parser = argparse.ArgumentParser(
        description="RPKI Repository Generator based on Context-Free Grammar"
    )
    
    # Structural parameters
    parser.add_argument("--depth", type=int, default=3,
                        help="Maximum depth of CA hierarchy")
    parser.add_argument("--max-branch", type=int, default=2,
                        help="Maximum number of children per CA")
    parser.add_argument("--min-branch", type=int, default=1,
                        help="Minimum number of children per CA (for sparse trees, auto-clamped to <= max_branch)")
    
    # Tree structure type (4 options)
    parser.add_argument("--tree-type", type=str, default="full",
                        choices=["full", "random", "sparse", "skeleton"],
                        help="Tree structure type: full (every internal node has max_branch children), "
                             "random ([0, max_branch] children, may terminate early), "
                             "sparse ([min_branch, max_branch] children), "
                             "skeleton (spine to max depth, wide at deepest level)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility (for non_full/random trees)")
    
    # Quantity parameters
    parser.add_argument("--num-roa", type=int, default=1,
                        help="Number of ROAs per CA")
    parser.add_argument("--num-mft", type=int, default=1,
                        help="Number of Manifests per CA")
    parser.add_argument("--num-crl", type=int, default=1,
                        help="Number of CRLs per CA")
    
    # Performance parameters
    parser.add_argument("--reuse-keys", type=str, default="per_type",
                        choices=["true", "per_type", "false"],
                        help="EE key reuse mode: true (fastest, OctoRPKI incompatible), "
                             "per_type (OctoRPKI compatible, manifest and ROAs use separate keys), "
                             "false (slowest, each object has unique key)")
    parser.add_argument("--key-size", type=int, default=2048,
                        help="RSA key size")
    
    # Output parameters
    parser.add_argument("--out", type=str, default="cfg_output",
                        help="Output directory")
    parser.add_argument("--base-uri", type=str,
                        default="rsync://localhost:8730/repo",
                        help="Base rsync URI")
    parser.add_argument("--no-clean", action="store_true",
                        help="Don't clean output directory before generation (keep old files)")
    
    args = parser.parse_args()

    # Parse reuse_keys argument
    reuse_keys_map = {
        "true": True,
        "per_type": "per_type",
        "false": False
    }
    reuse_keys_value = reuse_keys_map[args.reuse_keys.lower()]

    # Create configuration
    config = GeneratorConfig(
        depth=args.depth,
        max_branch=args.max_branch,
        min_branch=args.min_branch,
        tree_type=args.tree_type,
        random_seed=args.seed,
        num_roa=args.num_roa,
        num_mft=args.num_mft,
        num_crl=args.num_crl,
        reuse_keys=reuse_keys_value,
        key_size=args.key_size,
        output_dir=args.out,
        base_uri=args.base_uri,
        clean_output=not args.no_clean
    )
    
    # Generate repository
    print("Generating RPKI repository based on CFG...")
    print(f"  Tree Type: {config.tree_type}")
    print(f"  Depth: {config.depth}")
    print(f"  Max Branch: {config.max_branch}")
    print(f"  Min Branch: {config.min_branch}")
    if config.random_seed is not None:
        print(f"  Random Seed: {config.random_seed}")
    print(f"  Num ROA per CA: {config.num_roa}")
    print(f"  Num MFT per CA: {config.num_mft}")
    print(f"  Num CRL per CA: {config.num_crl}")
    print()
    
    generator = RPKICFGGenerator(config)
    root_ca = generator.generate()
    
    # Print statistics
    stats = generator.get_stats()
    print("Repository generated successfully!")
    print(f"  Output directory: {config.output_dir}")
    print(f"  TAL file: {generator.tal_path}")
    print()
    print("Statistics:")
    print(f"  Total CAs: {stats['total_ca']}")
    print(f"  Total ROAs: {stats['total_roa']}")
    print(f"  Total CRLs: {stats['total_crl']}")
    print(f"  Total Manifests: {stats['total_mft']}")
    print(f"  Leaf CAs: {stats['leaf_ca']}")
    print(f"  Max Depth: {stats['max_depth']}")


if __name__ == "__main__":
    main()
