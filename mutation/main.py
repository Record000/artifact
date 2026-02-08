from rpki.cert.TACert import CACertificateBuilder
from rpki.crl.crl import CRLBuilder, CRLConfig, RevokeCertConfig, CrlNumConfig
from rpki.mft.mft import RPKIManifest, MFTConfig
from rpki.cert.EECert import EECertConfig
from rpki.roa.roa import ROABuilder, ROAConfig
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from rpki.xml.notification import NotificationXml
from rpki.xml.snapshot import SnapshotXml
from rpki.xml.delta import DeltaXml
import os
import json
import shutil
import random
import uuid
import hashlib
from rpki.cert.CertParser import certParser, eeCertParser
from rpki.cert.config import CACertConfig, signatureAlgorithmConfig, validityConfig, basicConstraintsConfig, keyUsageConfig, \
    crlConfig, siaConfig, aiaConfig, certpoliciesConfig, ipaddrsConfig, asidConfig, keyUsage, asid, asidRange, ipv4addr, ipv6addr, \
    ipv4AddrRange, ipv6AddrRange
from rpki.mutator.CertMutator import CertMutator
import traceback
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5280, rfc3779
from pyasn1.type import univ, char
from pyasn1.codec.der import encoder
from datetime import datetime, timezone
import sys
import time

class Log:
    RESET = "\033[0m"
    RED   = "\033[31m"
    GREEN = "\033[32m"
    BLUE  = "\033[34m"

    @staticmethod
    def _now():
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    @staticmethod
    def _log(color, *args, sep=" ", end="\n", file=sys.stdout):
        msg = sep.join(str(a) for a in args)
        timestamp = Log._now()
        file.write(f"{color}[{timestamp}] {msg}{Log.RESET}{end}")
        file.flush()

    @staticmethod
    def info(*args, **kwargs):
        Log._log(Log.BLUE, *args, **kwargs)

    @staticmethod
    def success(*args, **kwargs):
        Log._log(Log.GREEN, *args, **kwargs)

    @staticmethod
    def error(*args, **kwargs):
        Log._log(Log.RED, *args, file=sys.stderr, **kwargs)

ID_AD_CA_REPOSITORY = univ.ObjectIdentifier('1.3.6.1.5.5.7.48.5')
ID_AD_RPKI_MANIFEST = univ.ObjectIdentifier('1.3.6.1.5.5.7.48.10')
ID_CP_RPKI = univ.ObjectIdentifier('1.3.6.1.5.5.7.14.2') # RFC6484

RPKI_ALLOWED_EXTENSIONS = {
    rfc5280.id_ce_basicConstraints,           # 2.5.29.19
    rfc5280.id_ce_subjectKeyIdentifier,       # 2.5.29.14 (SKI)
    rfc5280.id_ce_authorityKeyIdentifier,     # 2.5.29.35 (AKI)
    rfc5280.id_ce_keyUsage,                   # 2.5.29.15
    rfc5280.id_ce_cRLDistributionPoints,     # 2.5.29.31
    rfc5280.id_pe_authorityInfoAccess,        # 1.3.6.1.5.5.7.1.1 (AIA)
    rfc5280.id_pe_subjectInfoAccess,          # 1.3.6.1.5.5.7.1.11 (SIA)
    rfc5280.id_ce_certificatePolicies,        # 2.5.29.32
    rfc3779.id_pe_ipAddrBlocks,               # 1.3.6.1.5.5.7.1.7
    rfc3779.id_pe_autonomousSysIds,           # 1.3.6.1.5.5.7.1.8
}

ID_SHA256_WITH_RSA_ENCRYPTION = univ.ObjectIdentifier('1.2.840.113549.1.1.11')
ID_RSA_ENCRYPTION = univ.ObjectIdentifier('1.2.840.113549.1.1.1')

def check_signature_compliance(cert, tbs):
    tbs_alg = tbs['signature']['algorithm']
    if tbs_alg != ID_SHA256_WITH_RSA_ENCRYPTION:
        return False, f"Invalid TBS signature algorithm: {tbs_alg}"

    cert_alg = cert['signatureAlgorithm']['algorithm']
    if cert_alg != tbs_alg:
        return False, "Signature algorithm mismatch between outer and inner fields"

    spki = tbs['subjectPublicKeyInfo']
    pub_key_alg = spki['algorithm']['algorithm']
    if pub_key_alg != ID_RSA_ENCRYPTION:
        return False, f"Invalid Public Key algorithm: {pub_key_alg} (MUST be RSA)"

    try:
        from pyasn1_modules import rfc2437 
        
        pub_key_bits = spki['subjectPublicKey'].asOctets()
        rsa_pub, _ = decoder.decode(pub_key_bits, asn1Spec=rfc2437.RSAPublicKey())
        
        modulus = int(rsa_pub['modulus'])
        bit_length = modulus.bit_length()
        
        if bit_length < 2032 or bit_length > 2064: 
            return False, f"Invalid RSA Key length: {bit_length} bits (MUST be 2048)"
            
    except Exception as e:
        return False, f"Failed to verify RSA key length: {e}"

    return True, "Signature and Key algorithms are compliant"

def check_ski_compliance(tbs, ext_dict):

    if rfc5280.id_ce_subjectKeyIdentifier not in ext_dict:
        return False, "Missing mandatory SKI extension"

    ski_ext = ext_dict[rfc5280.id_ce_subjectKeyIdentifier]

    if ski_ext['critical'].hasValue() and ski_ext['critical']:
        return False, "SKI extension MUST be non-critical"

    try:
        ski_actual_val, _ = decoder.decode(ski_ext['extnValue'], 
                                           asn1Spec=rfc5280.SubjectKeyIdentifier())
        
        spki = tbs['subjectPublicKeyInfo']
        if not spki['subjectPublicKey'].hasValue():
            return False, "SubjectPublicKey is missing"

        public_key_bytes = spki['subjectPublicKey'].asOctets()
        
        expected_hash = hashlib.sha1(public_key_bytes).digest()
        actual_hash = ski_actual_val.asOctets()

        if len(actual_hash) != 20:
            return False, f"SKI length is not 160-bit (Expected 20 bytes, got {len(actual_hash)})"

        if actual_hash != expected_hash:
            return False, f"SKI value mismatch! Mutated value: {actual_hash.hex()}, Expected: {expected_hash.hex()}"

        return True, "SKI is valid"

    except Exception as e:
        return False, f"Error parsing SKI value: {str(e)}"


def parse_asn1_time(time_choice):
    t_name = time_choice.getName()
    t_str = str(time_choice.getComponent())
    
    try:
        if t_name == 'utcTime':
            return datetime.strptime(t_str, '%y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
        else:
            return datetime.strptime(t_str, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
    except Exception as e:
        return None

def debug_log(msg):
    Log.info(f"[DEBUG RFC_EVAL] {msg}")

def check_ip_resources(ip_ext):
    try:
        ip_val, rest = decoder.decode(
            ip_ext['extnValue'],
            asn1Spec=rfc3779.IPAddrBlocks()
        )
        if rest != b'':
            debug_log("Trailing garbage in IPAddrBlocks")
            return False

        for af in ip_val:
            afi = af['addressFamily']
            if len(afi) not in (2, 3):  # IPv4=2, IPv6=2(+safi)
                debug_log(f"Invalid AFI length: {len(afi)}")
                return False

            choice = af['ipAddressChoice']
            if choice.getName() == 'inherit':
                continue

            for addr in choice['addressesOrRanges']:
                name = addr.getName()
                if name == 'addressPrefix':
                    bits = addr.getComponent()
                    if len(bits) > (32 if afi == b'\x00\x01' else 128):
                        debug_log("IP prefix too long")
                        return False

                elif name == 'addressRange':
                    lo = addr['addressRange']['min']
                    hi = addr['addressRange']['max']
                    if len(lo) != len(hi):
                        debug_log("IP range min/max length mismatch")
                        return False
                    if int(lo) > int(hi):
                        debug_log("IP range min > max")
                        return False
                else:
                    debug_log("Unknown IPAddressOrRange choice")
                    return False

        return True

    except Exception as e:
        debug_log(f"Malformed IPAddrBlocks: {e}")
        return False

def check_as_resources(as_ext, is_ta=False):
    try:
        as_val, _ = decoder.decode(
            as_ext['extnValue'],
            asn1Spec=rfc3779.ASIdentifiers()
        )

        if as_val['asnum'].getName() == 'asIdsOrRanges':
            for entry in as_val['asnum']:
                if entry.getName() == 'asRange':
                    lo = int(entry['asRange']['min'])
                    hi = int(entry['asRange']['max'])
                    if lo == 0 or hi == 4294967295:
                        debug_log("AS range includes reserved ASNs")
                        return False
                    if not is_ta and (lo == 0 and hi == 4294967295):
                        debug_log("Non-TA claims full ASN space")
                        return False
        return True
    except Exception as e:
        debug_log(f"Malformed ASIdentifiers: {e}")
        return False

def evaluate_rfc(cert_der: bytes) -> bool:

    Log.success("\n==================== EVALUATE VALIDATION ====================")
    try:
        try:
            cert, _ = decoder.decode(cert_der, asn1Spec=rfc5280.Certificate())
            tbs = cert['tbsCertificate']
        except Exception as e:
            debug_log(f"Decoding failed (Malformed ASN.1): {e}")
            return False

        # 2. Version check (Section 4.1: MUST be 3, value=2)
        if not tbs['version'].hasValue() or tbs['version'] != 2:
            debug_log("Invalid Version (MUST be v3)")
            return False

        # 3.Signature Algorithm
        # The algorithm used in this profile is specified in [RFC6485].
        is_alg_valid, alg_msg = check_signature_compliance(cert, tbs)
        if not is_alg_valid:
            debug_log(alg_msg)
            return False

        # 4. Serial Number check (Section 4.2: MUST be positive)
        # 5280 ： Given the uniqueness requirements above, serial numbers can be
        # expected to contain long integers.  Certificate users MUST be able to
        # handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
        # use serialNumber values longer than 20 octets.

        # 6487 ： The serial number value is a positive integer that is unique for each
        # certificate issued by a given CA

        if not tbs['serialNumber'].hasValue():
            return False
            
        serial_obj = tbs['serialNumber']
        serial_val = int(serial_obj)
        
        # A. check whether its a positive (RFC 6487 Section 4.2)
        if serial_val <= 0:
            debug_log("SerialNumber must be a positive integer")
            return False
            
        # B. check length (RFC 5280 Section 4.1.2.2: MAX 20 octets)
        try:
            der_serial = encoder.encode(serial_obj)
            content_length = len(der_serial) - 2 
            if content_length > 20:
                debug_log(f"SerialNumber is too long ({content_length} octets, MAX is 20)")
                return False
        except Exception as e:
            debug_log(f"Error encoding Serial Number for length check: {e}")
            return False
        
        validity = tbs['validity']
        not_before = parse_asn1_time(validity['notBefore'])
        not_after = parse_asn1_time(validity['notAfter'])
        
        if not_before is None or not_after is None:
            debug_log("Invalid Time format in Validity")
            return False
            
        now = datetime.now(timezone.utc)
        
        if now < not_before:
            debug_log(f"Certificate is not yet valid (Starts at {not_before})")
            return False 
            
        if now > not_after:
            debug_log(f"Certificate has expired (Expired at {not_after})")
            return False 
            
        if not_before >= not_after:
            debug_log("notBefore is later than notAfter")
            return False
        
        # 4. Issuer & Subject check (Section 4.4 & 4.5)
        def check_name_structure(name_obj, label):
            if not name_obj.hasValue(): return False
            try:
                rdn_sequence = name_obj.getComponent() 
                has_cn = False
                for rdn in rdn_sequence:
                    for attr in rdn:
                        if attr['type'] == rfc5280.id_at_commonName:
                            has_cn = True
                            val, _ = decoder.decode(attr['value'].asOctets())
                            if not isinstance(val, char.PrintableString):
                                debug_log(f"{label} CommonName is not PrintableString")
                                return False
                if not has_cn:
                    debug_log(f"{label} missing mandatory CommonName")
                    return False
                return True
            except: return False

        if not check_name_structure(tbs['issuer'], "Issuer"): return False
        if not check_name_structure(tbs['subject'], "Subject"): return False

        is_self_signed = (tbs['issuer'] == tbs['subject'])

        # 5. extension check (Section 4.8)
        if not tbs['extensions'].hasValue():
            debug_log("Mandatory extensions block is missing")
            return False
            
        ext_dict = {}
        for ext in tbs['extensions']:
            if not ext['extnID'].hasValue(): continue
            oid = ext['extnID']
            
            if oid not in RPKI_ALLOWED_EXTENSIONS:
                debug_log(f"Forbidden extension found (OID: {oid}). Fuzzer mutated OID improperly.")
                return False
            
            ext_dict[oid] = ext

        if rfc5280.id_ce_subjectKeyIdentifier not in ext_dict:
            debug_log("Missing mandatory Subject Key Identifier (SKI)")
            return False
        is_ski_valid, msg = check_ski_compliance(tbs, ext_dict)
        if not is_ski_valid:
            debug_log(msg)
            return False

        # 5.1 Basic Constraints (Section 4.8.1: MUST be critical, MUST be CA=True)
        if rfc5280.id_ce_basicConstraints not in ext_dict: 
            debug_log("Missing mandatory BasicConstraints")
            return False
        bc_ext = ext_dict[rfc5280.id_ce_basicConstraints]
        if not bc_ext['critical'].hasValue() or not bc_ext['critical']: 
            debug_log("BasicConstraints MUST be critical")
            return False
        bc_val, _ = decoder.decode(bc_ext['extnValue'], asn1Spec=rfc5280.BasicConstraints())
        if not bc_val['cA'].hasValue() or not bc_val['cA']: 
            debug_log("BasicConstraints cA MUST be True for CA certificates")
            return False
        if bc_val['pathLenConstraint'].isValue:
            debug_log("BasicConstraints pathLenConstraint MUST NOT be present")
            return False

        # 5.2 Key Usage (Section 4.8.4: MUST be critical)
        if rfc5280.id_ce_keyUsage not in ext_dict:
            debug_log("Missing mandatory KeyUsage")
            return False
        ku_ext = ext_dict[rfc5280.id_ce_keyUsage]
        if not ku_ext['critical'].hasValue() or not ku_ext['critical']:
            debug_log("KeyUsage MUST be critical")
            return False
        ku_val, _ = decoder.decode(ku_ext['extnValue'], asn1Spec=rfc5280.KeyUsage())
        ku_str = "".join([str(b) for b in ku_val])
        if len(ku_str) < 7 or ku_str[5] != '1' or ku_str[6] != '1':
            debug_log("Invalid KeyUsage bits for CA")
            return False

        # 5.3 SIA (Section 4.8.8: MUST be non-critical, MUST have rsync URIs)
        if rfc5280.id_pe_subjectInfoAccess not in ext_dict: 
            debug_log("Missing mandatory Subject Information Access (SIA)")
            return False
        sia_ext = ext_dict[rfc5280.id_pe_subjectInfoAccess]
        if sia_ext['critical'].hasValue() and sia_ext['critical']: 
            debug_log("SIA MUST be non-critical")
            return False
        sia_val, _ = decoder.decode(sia_ext['extnValue'], asn1Spec=rfc5280.SubjectInfoAccessSyntax())
        has_repo = has_manifest = False
        for desc in sia_val:
            method = desc['accessMethod']
            loc = desc['accessLocation']
            if loc.getName() == 'uniformResourceIdentifier':
                uri = str(loc.getComponent())
                if uri.startswith("rsync://"):
                    if method == ID_AD_CA_REPOSITORY: has_repo = True
                    if method == ID_AD_RPKI_MANIFEST: has_manifest = True
        if not (has_repo and has_manifest): 
            debug_log("SIA missing mandatory rsync repo or manifest URI")
            return False

        # 5.4 IP/AS Resources (Section 4.8.10/11: MUST be critical)
        has_ip = rfc3779.id_pe_ipAddrBlocks in ext_dict
        if has_ip:
            if not check_ip_resources(ext_dict[rfc3779.id_pe_ipAddrBlocks]):
                return False
        
        has_as = rfc3779.id_pe_autonomousSysIds in ext_dict
        if not (has_ip or has_as):
            debug_log("Missing mandatory Resource extensions (IP or AS)")
            return False
        if has_ip and not ext_dict[rfc3779.id_pe_ipAddrBlocks]['critical']: return False
        if has_as and not ext_dict[rfc3779.id_pe_autonomousSysIds]['critical']:
            return False

        # 5.5 AIA & CDP (Section 4.8.6/7)
        if not is_self_signed:
            # Subordinate CA: MUST have AIA and CDP, MUST be non-critical
            if rfc5280.id_pe_authorityInfoAccess not in ext_dict: 
                debug_log("Subordinate CA missing mandatory AIA")
                return False
            if rfc5280.id_ce_cRLDistributionPoints not in ext_dict: 
                debug_log("Subordinate CA missing mandatory CDP")
                return False
        else:
            # Self-signed (TA): MUST NOT have AIA or CDP
            if rfc5280.id_pe_authorityInfoAccess in ext_dict: 
                debug_log("Self-signed TA MUST NOT have AIA")
                return False
            if rfc5280.id_ce_cRLDistributionPoints in ext_dict: 
                debug_log("Self-signed TA MUST NOT have CDP")
                return False
            
        # 5.6 Certificate Policies check (RFC 6487 Section 4.8.9)
        if rfc5280.id_ce_certificatePolicies not in ext_dict:
            debug_log("Missing mandatory Certificate Policies")
            return False
        cp_ext = ext_dict[rfc5280.id_ce_certificatePolicies]
        if not cp_ext['critical'].hasValue() or not cp_ext['critical']:
            debug_log("Certificate Policies MUST be critical")
            return False

        cp_val, _ = decoder.decode(cp_ext['extnValue'], asn1Spec=rfc5280.CertificatePolicies())
        if len(cp_val) != 1:
            debug_log(f"Invalid Policy count: {len(cp_val)} (MUST be exactly 1)")
            return False

        policy_oid = cp_val[0]['policyIdentifier']
        if str(policy_oid) != "1.3.6.1.5.5.7.14.2":
            debug_log(f"Invalid Policy OID: {policy_oid}")
            return False

        debug_log("Validation PASSED (Compliant with RFC 6487)")
        return True

    except Exception as e:
        debug_log(f"Unexpected Critical Error during evaluation: {repr(e)}")
        traceback.print_exc() 
        return False

def build_ta():
    version = 2
    serial_number = 1
    signature_algorithm = signatureAlgorithmConfig(
        oid='1.2.840.113549.1.1.11', 
        parameters=None
    )
    issuer = 'ca_certificate'
    validity = validityConfig(
        not_before="20241125055723Z", 
        not_after="20301125055723Z"
    )
    subject = 'ca_certificate'
    # subject_public_key_info = None
    basic_constraints = basicConstraintsConfig(
        critical=True, 
        ca=True, 
        path_length=None
    )
    key_identifier_critical = False
    
    # '000001100'
    key_usage_t = keyUsage()
    key_usage_t.key_cert_sign = True
    key_usage_t.crl_sign = True
    key_usage = keyUsageConfig(
        critical=True, 
        key_usage=key_usage_t
    )
    
    # aki_critical = False
    crl_distribution_points = crlConfig(
        critical=False, 
        crl_uris=["rsync://localhost:8080/myrpki/ca_certificate/revoked.crl"]
    )
    authority_information_access = aiaConfig(
        critical=False, 
        ca_issuer_uri="rsync://localhost:8080/myrpki/ca_certificate"
    )
    # rrdp_uri="https://rpki.odysseus.uno/rrdp/notification.xml",
    # ca_uri="rsync://localhost:8080/myrpki/ca_certificate",
    # mft_uri="rsync://localhost:8080/myrpki/ca_certificate/manifest.mft"
    subject_information_access = siaConfig(
        critical=False, 
        accessed= [
            {
                "access_method": "ca_repository",
                "access_location": "rsync://localhost:8080/myrpki/ca_certificate"
            },
            {
                "access_method": "id-ad-rpkiManifest",
                "access_location": "rsync://localhost:8080/myrpki/ca_certificate/manifest.mft"
            }
            # {
            #     "access_method": "id-ad-rpkiNotify",
            #     "access_location": "https://rpki.odysseus.uno/rrdp/notification.xml"
            # }
        ]
    )
    certificate_policies = certpoliciesConfig(
        critical=True, 
        policy_identifiers=['1.3.6.1.5.5.7.14.2']
    )
    ip_address = ipaddrsConfig(
        critical=True, 
        ipv4_addrs=[ipv4addr('166.111.0.0/20')],
        ipv6_addrs=[ipv6addr('::/8')]
    )
    as_id = asidConfig(
        critical=True, 
        asids=[asidRange(0, 4294967295)]
    )
    config = CACertConfig(
        version=version, serial_number=serial_number, signature_algorithm=signature_algorithm,
        issuer=issuer, validityconfig=validity, subject=subject,
        basic_constraints=basic_constraints, key_identifier_critical=key_identifier_critical,
        key_usage=key_usage, crl_distribution_points=crl_distribution_points, aki_critical=None,
        authority_information_access=authority_information_access, subject_information_access=subject_information_access,
        certificate_policies=certificate_policies, ip_address=ip_address, as_id=as_id
    )
    
    builder = CACertificateBuilder(config=config, debug=False)

    builder.set_version()
    builder.set_serial_number()
    builder.set_signature_algorithm()
    builder.set_issuer()
    builder.set_validity()
    builder.set_subject()
    builder.set_subjectPublicKeyInfo()
    builder.set_issuer_unique_id()
    builder.set_subject_unique_id()
    builder.basic_constraints_extension()
    builder.key_identifier_extension()
    builder.key_usage_extension()
    builder.subject_information_access_extension()
    builder.certificate_policies_extension()
    builder.ip_address_extension()
    builder.as_id_extension()

    builder.build_certificate()
    builder.export_certificate('./my_repo/ca_certificate.cer')
    # Log.info("Certificate exported to ./my_repo/ca_certificate.cer")

    if os.path.exists("./my_repo/key") is False:
        os.mkdir("./my_repo/key")
    builder.export_private_key('./my_repo/key/ta_private_key.pem')
    # Log.info("Private key exported to ./my_repo/key/ta_private_key.pem")
    builder.export_public_key('./my_repo/key/ta_public_key.pem')
    # Log.info("Public key exported to ./my_repo/key/ta_public_key.pem")

    with open("./my_repo/ca_certificate.cer", "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    # Log.info(cert)
    public_key_info_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Log.info(public_key_info_der)
    tal_contents = f"rsync://localhost:8080/myrpki/ca_certificate.cer\n\n".encode()
    tal_contents += base64.b64encode(public_key_info_der)

    if os.path.exists("./my_repo/tal") is False:
        os.mkdir("./my_repo/tal")
    with open("./my_repo/tal/ta.tal", "wb") as tal_file:
        tal_file.write(tal_contents)
    # Log.info("TAL exported to ./my_repo/tal/ta.tal")

def build_ta_from_json(file_path):
    cert_parser = certParser(file_path)
    version = cert_parser.version()
    serial_number = cert_parser.serial_number()
    signature = cert_parser.signature()
    issuer = cert_parser.issuer()
    validaty = cert_parser.validaty()
    subject = cert_parser.subject()
    spki_algorithm = cert_parser.spki_algorithm()
    certificate_policy = cert_parser.certificate_policy()
    basic_constraints = cert_parser.basic_constraints()
    key_usage = cert_parser.key_usage()
    key_identifier = cert_parser.key_identifier()
    subject_information_access = cert_parser.subject_information_access()
    ipaddr_blocks = cert_parser.ipaddr_blocks()
    asnum_blocks = cert_parser.asnum_blocks()

    config = CACertConfig(
        version=version,
        serial_number=serial_number,
        signature_algorithm=signature,
        issuer=issuer,
        validityconfig=validaty,
        subject=subject,
        basic_constraints=basic_constraints,
        key_identifier_critical=key_identifier,
        key_usage=key_usage,
        subject_information_access=subject_information_access,
        ip_address=ipaddr_blocks,
        as_id=asnum_blocks,
        certificate_policies=certificate_policy,
        json_file_path=file_path
    )

    builder = CACertificateBuilder(config, debug=False)
    builder.set_version()
    builder.set_serial_number()
    builder.set_signature_algorithm()
    builder.set_issuer()
    builder.set_validity()
    builder.set_subject()
    builder.set_subjectPublicKeyInfo()
    builder.set_issuer_unique_id()
    builder.set_subject_unique_id()
    builder.basic_constraints_extension()
    builder.key_identifier_extension()
    builder.key_usage_extension()
    builder.subject_information_access_extension()
    builder.certificate_policies_extension()
    builder.ip_address_extension()
    builder.as_id_extension()

    builder.build_certificate()    

    builder.export_certificate('./my_repo/ca_certificate.cer')
    # Log.info("Certificate exported to ./my_repo/ca_certificate.cer")

    if os.path.exists("./my_repo/key") is False:
        os.mkdir("./my_repo/key")
    builder.export_private_key('./my_repo/key/ta_private_key.pem')
    # Log.info("Private key exported to ./my_repo/key/ta_private_key.pem")
    builder.export_public_key('./my_repo/key/ta_public_key.pem')
    # Log.info("Public key exported to ./my_repo/key/ta_public_key.pem")

    with open("./my_repo/ca_certificate.cer", "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    # Log.info(cert)
    public_key_info_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Log.info(public_key_info_der)
    tal_contents = f"rsync://localhost:8080/myrpki/ca_certificate.cer\n\n".encode()
    tal_contents += base64.b64encode(public_key_info_der)

    if os.path.exists("./my_repo/tal") is False:
        os.mkdir("./my_repo/tal")
    with open("./my_repo/tal/ta.tal", "wb") as tal_file:
        tal_file.write(tal_contents)
    # Log.info("TAL exported to ./my_repo/tal/ta.tal")

def build_subca():
    version = 2
    serial_number = 2
    signature_algorithm = signatureAlgorithmConfig(
        oid='1.2.840.113549.1.1.11', 
        parameters=None
    )
    issuer = 'ca_certificate'
    validity = validityConfig(
        not_before="20241125055723Z", 
        not_after="20301125055723Z"
    )
    subject = 'sub_ca'
    # subject_public_key_info = None
    basic_constraints = basicConstraintsConfig(
        critical=True, 
        ca=True, 
        path_length=None
    )
    key_identifier_critical = False
    
    # '000001100'
    key_usage_t = keyUsage()
    key_usage_t.key_cert_sign = True
    key_usage_t.crl_sign = True
    key_usage = keyUsageConfig(
        critical=True, 
        key_usage=key_usage_t
    )
    
    # aki_critical = False
    crl_distribution_points = crlConfig(
        critical=False, 
        crl_uris=["rsync://localhost:8080/myrpki/ca_certificate/revoked.crl"]
    )
    authority_information_access = aiaConfig(
        critical=False, 
        ca_issuer_uri="rsync://localhost:8080/myrpki/ca_certificate.cer"
    )
    subject_information_access = siaConfig(
        critical=False, 
        accessed= [
            {
                "access_method": "ca_repository",
                "access_location": "rsync://localhost:8080/myrpki/ca_certificate/sub_ca"
            },
            {
                "access_method": "id-ad-rpkiManifest",
                "access_location": "rsync://localhost:8080/myrpki/ca_certificate/sub_ca/manifest.mft"
            }
        ]
    )
    certificate_policies = certpoliciesConfig(
        critical=True, 
        policy_identifiers=['1.3.6.1.5.5.7.14.2']
    )
    ip_address = ipaddrsConfig(
        critical=True, 
        ipv4_addrs=[ipv4addr('166.111.0.0/22')],
        ipv6_addrs=[ipv6addr('::/8')]
    )
    as_id = asidConfig(
        critical=True, 
        asids=[asidRange(0, 4294967295)]
    )
    config = CACertConfig(
        version=version, serial_number=serial_number, signature_algorithm=signature_algorithm,
        issuer=issuer, validityconfig=validity, subject=subject,
        basic_constraints=basic_constraints, key_identifier_critical=key_identifier_critical,
        key_usage=key_usage, crl_distribution_points=crl_distribution_points, aki_critical=False,
        authority_information_access=authority_information_access, subject_information_access=subject_information_access,
        certificate_policies=certificate_policies, ip_address=ip_address, as_id=as_id
    )
    
    issuer_rsa_key_path = "./my_repo/key/ta_private_key.pem"

    issuer_rsa_key = serialization.load_pem_private_key(open(issuer_rsa_key_path, 'rb').read(), password=None, backend=default_backend())
    builder = CACertificateBuilder(config=config, debug=False)

    builder.set_version()
    builder.set_serial_number()
    builder.set_signature_algorithm()
    builder.set_issuer()
    builder.set_validity()
    builder.set_subject()
    builder.set_subjectPublicKeyInfo()
    builder.set_issuer_unique_id()
    builder.set_subject_unique_id()
    builder.basic_constraints_extension()
    builder.key_identifier_extension()
    builder.authority_key_identifier_extension(issuer_public_key=issuer_rsa_key.public_key())
    builder.key_usage_extension()
    builder.crl_distribution_points_extension()
    builder.authority_information_access_extension()
    builder.subject_information_access_extension()
    builder.certificate_policies_extension()
    builder.ip_address_extension()
    builder.as_id_extension()

    builder.build_certificate(issuer_private_key=issuer_rsa_key)
    if not os.path.exists('./my_repo/ca_certificate'):
        os.makedirs('./my_repo/ca_certificate')
    builder.export_certificate('./my_repo/ca_certificate/sub_ca.cer')
    builder.export_private_key('./my_repo/key/sub_ca_private_key.pem')
    builder.export_public_key('./my_repo/key/sub_ca_public_key.pem')

def build_tal(ca_path, export_path):

    with open(ca_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    # Log.info(cert)
    public_key_info_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Log.info(public_key_info_der)
    tal_contents = f"rsync://localhost:8080/myrpki/ca_certificate.cer\n\n".encode()
    tal_contents += base64.b64encode(public_key_info_der)

    if os.path.exists("./my_repo/tal") is False:
        os.mkdir("./my_repo/tal")
    with open(export_path, "wb") as tal_file:
        tal_file.write(tal_contents)
    # Log.info("TAL exported to "+export_path)

def build_ca(issuer_private_key, ca_path, config, key_export_path, is_ta=False):

    if not is_ta:
        mutation_targets = [
            "version", "serial_number", "validity", "key_usage", "basic_constraints" 
            "subject_information_access", "certificate_policies", "signature_algorithm",
            "ip_address", "as_id"
        ]
        target = random.choice(mutation_targets)
        Log.error(f"[MUTATE VALUE]: {target}")
        # mutator = [CertMutator(target)]
        mutator = []
    else:
        mutator = []

    builder = CACertificateBuilder(config=config, mutator=mutator, debug=False)
    
    builder.set_version(); builder.set_serial_number(); builder.set_signature_algorithm()
    builder.set_issuer(); builder.set_validity(); builder.set_subject(); builder.set_subjectPublicKeyInfo()
    builder.set_issuer_unique_id(); builder.set_subject_unique_id(); builder.basic_constraints_extension()
    builder.key_identifier_extension()
    
    if not is_ta:
        builder.authority_key_identifier_extension(issuer_public_key=issuer_private_key.public_key())
        builder.crl_distribution_points_extension()
        builder.authority_information_access_extension()
        
    builder.key_usage_extension(); builder.subject_information_access_extension()
    builder.certificate_policies_extension(); builder.ip_address_extension(); builder.as_id_extension()

    builder.build_certificate(issuer_private_key=issuer_private_key)
    builder.export_certificate(ca_path)
    
    if not os.path.exists(os.path.dirname(key_export_path)): 
        os.makedirs(os.path.dirname(key_export_path))
    builder.export_private_key(key_export_path)

    if not is_ta:
        with open(ca_path, "rb") as f: 
            cert_der = f.read()
        is_valid_rfc = evaluate_rfc(cert_der)
        Log.error(f"Certificate {ca_path} RFC Status: {'VALID' if is_valid_rfc else 'INVALID'}")

def build_crl(issuer_private_key_path, crl_path, config:CRLConfig=None):
    issuer_private_key_path = issuer_private_key_path
    issuer_private_key = serialization.load_pem_private_key(open(issuer_private_key_path, 'rb').read(),
                                                            password=None, backend=default_backend())
    builder = CRLBuilder(issuer_private_key=issuer_private_key, config=config)
    builder.set_version()
    builder.set_signature_algorithm()
    builder.set_issuer()
    builder.set_this_update()
    builder.set_next_update()
    builder.authority_key_identifier_extension()
    builder.crl_number_extension()
    crl = builder.build_crl()
    builder.export_crl(crl_path)

def build_mft(issuer_private_key_path, mft_config, mft_path):
    with open(issuer_private_key_path, 'rb') as f:
        issuer_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    # mft_config = MFTConfig()
    # mft_config.file_names = file_names
    mft = RPKIManifest(issuer_private_key, config=mft_config)
    mft.set_version()
    mft.set_digest_algorithm()
    mft.set_encap_content_info()
    subject_key_identifier_hex = mft.set_eecert(issuer_private_key=issuer_private_key)
    mft.set_certificate_set()
    mft.set_crls()
    mft.set_signer_info(subject_key_identifier_hex)
    mft.export_cms(file_path=mft_path)

def build_roa(issuer_private_key_path, roa_config, roa_path):
    # issuer_rsa_key_path = "./my_repo/key/sub_ca_private_key.pem"
    with open(issuer_private_key_path, 'rb') as f:
        issuer_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    roa = ROABuilder(issuer_private_key=issuer_private_key, config=roa_config)
    roa.set_version()
    roa.set_digest_algorithm()
    roa.set_roaauthz()
    roa.set_encap_content_info()
    subject_key_identifier_hex = roa.set_eecert(issuer_private_key=issuer_private_key)
    roa.set_certificate_set()
    roa.set_crls()
    roa.set_signer_info(subject_key_identifier_hex)
    roa.export_cms(file_path=roa_path)

def build_rrdp(session_id="f2eb4f5d-e085-4edb-8030-f42f38424a9f", serial="2", root_dir="./my_repo/",
               root_https_url="https://rpki.odysseus.uno/rrdp/", rsync_root_uri="rsync://localhost:8080/myrpki/", 
               target_dir="./my_repo/rrdp/"):
    notification = NotificationXml(str(session_id), serial)
    snapshot_target_dir = target_dir + str(session_id) + "/" + str(serial)
    if not os.path.exists(snapshot_target_dir):
        os.makedirs(snapshot_target_dir)

    snapshot = SnapshotXml(str(session_id), serial)

    for root, dirs, files in os.walk(root_dir):

        if "key" in dirs:
            dirs.remove("key")
        if "tal" in dirs:
            dirs.remove("tal")
        if "rrdp" in dirs:
            dirs.remove("rrdp")
        for file in files:
            file_path = os.path.join(root, file)
            # Log.info("file_path: ", file_path)
            rsync_uri = file_path.replace(root_dir, rsync_root_uri)
            # Log.info("rsync_uri: ", rsync_uri)
            snapshot.add_publish(rsync_uri, file_path)
    snap_target = snapshot_target_dir + "/snapshot.xml"
    snapshot.write(snap_target)
    notification.add_snapshot(root_https_url + str(session_id) + "/" + str(serial) + "/snapshot.xml", snap_target)
    
    if serial == "1":
        need_delta = False
    else:
        need_delta = True
    
    if need_delta:
        # delta.parse_snapshot(snapshot_path)
        default_path = target_dir + "/" + str(session_id)
        delta = DeltaXml(str(session_id), serial=serial, old_serial=str(int(serial)-1), default_path=default_path)

        delta.generate_delta()
        delta_target = snapshot_target_dir + "/delta.xml"
        delta.write(delta_target)
        notification.add_delta(root_https_url + str(session_id) + "/" + str(serial) + "/delta.xml", delta_target)
    
    notification_target = target_dir + "/notification.xml"
    # Log.info("notification_target: ", notification_target)
    notification.write(notification_target)

import secrets
import string
import random
def export_tal(ca_cert_path, tal_export_path):

    with open(ca_cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_der_x509_certificate(cert_data, default_backend())

    public_key_info_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    tal_contents = f"rsync://localhost:8080/myrpki/ca_certificate.cer\n\n".encode()
    tal_contents += base64.b64encode(public_key_info_der)

    tal_dir = os.path.dirname(tal_export_path)
    if not os.path.exists(tal_dir):
        os.makedirs(tal_dir, exist_ok=True)

    with open(tal_export_path, "wb") as tal_file:
        tal_file.write(tal_contents)
    Log.info(f"TAL exported to {tal_export_path}")
def generate_mutated_ca_name():
    length = random.randint(4, 12)
    name_chars = [secrets.choice(string.ascii_letters + string.digits) for _ in range(length)]
    if random.random() < 0.1:
        control_char = chr(random.randint(0, 31))
        insert_pos = random.randint(0, length-1)
        name_chars[insert_pos] = control_char
    return ''.join(name_chars)

def sync_ee_json(path, issuer, aki, crl_uri, signed_object_uri, aia_uri=None):
    if os.path.exists(path):
        with open(path, "r") as f: data = json.load(f)
        ee = data["content"]["certificates"][0]
        ee["tbs_certificate"]["issuer"]["common_name"] = issuer
        for ext in ee["tbs_certificate"]["extensions"]:
            if ext["extn_id"] == "authority_key_identifier":
                ext["extn_value"]["key_identifier"] = aki
            if ext["extn_id"] == "crl_distribution_points":
                ext["extn_value"][0]["distribution_point"] = [crl_uri]
            if ext["extn_id"] == "authority_information_access" and aia_uri:
                ext["extn_value"][0]["access_location"] = aia_uri
            if ext["extn_id"] == "subject_information_access":
                for acc in ext["extn_value"]:
                    if acc["access_method"] == "1.3.6.1.5.5.7.48.11":
                        acc["access_location"] = signed_object_uri
        with open(path, "w") as f: json.dump(data, f, indent=2)

class RPKINode:
    def __init__(self, level, parent=None):
        self.level = level
        self.parent = parent
        self.children = []
        self.name = generate_mutated_ca_name()
        self.ski = secrets.token_hex(20)
        self.uri = ""             
        self.physical_dir = ""     
        self.cert_path = ""       
        self.priv_key_path = ""   
        self.json_config_path = "" 
        self.mft_ee_json = ""     
        self.roa_ee_json = ""     

def build_topology(depth, branching_factor, ta_template, sub_template, mft_template, roa_template, tmp_dir):

    rsync_base = "rsync://localhost:8080/myrpki"
    root = RPKINode(level=0)
    all_nodes = [root]
    
    def mutate_ca_config(node, parent_node=None):
        node.json_config_path = os.path.join(tmp_dir, f"ca_L{node.level}_{node.name}.json")
        proto = ta_template if node.level == 0 else sub_template
        shutil.copy(proto, node.json_config_path)

        with open(node.json_config_path, "r") as f:
            data = json.load(f)

        # ============================================================
        # subject / issuer
        # ============================================================
        data["tbs_certificate"]["subject"]["common_name"] = node.name
        data["tbs_certificate"]["issuer"]["common_name"] = (
            parent_node.name if parent_node else node.name
        )

        # ============================================================
        # URI 
        # ============================================================
        parent_uri = parent_node.uri if parent_node else "rsync://localhost:8080/myrpki"
        node.uri = f"{parent_uri}/{node.name}" if parent_node else f"{parent_uri}"

        # ============================================================
        # SPKI （TA / CA ）
        # ============================================================
        spki = data["tbs_certificate"].get("subject_public_key_info")
        if spki and "algorithm" in spki:
            spki["algorithm"]["parameters"] = None

        # ============================================================
        # Extensions
        # ============================================================
        for ext in data["tbs_certificate"]["extensions"]:

            # ---------- SKI ----------
            if ext["extn_id"] == "key_identifier":
                ext["extn_value"] = node.ski

            # ---------- CRL DP ----------
            if ext["extn_id"] == "crl_distribution_points":
                ext["extn_value"][0]["distribution_point"] = [
                    f"{parent_uri}/revoked.crl"
                ]

            # ---------- SIA ----------
            if ext["extn_id"] == "subject_information_access":
                for acc in ext["extn_value"]:
                    if acc["access_method"] == "ca_repository":
                        acc["access_location"] = f"{node.uri}/"
                    if acc["access_method"] == "id-ad-rpkiManifest":
                        acc["access_location"] = f"{node.uri}/manifest.mft"

            # ========================================================
            # AIA —— only for subCA
            # ========================================================
            if parent_node and ext["extn_id"] == "authority_information_access":
                parent_cert_url = (
                    f"{parent_uri}/sub_ca.cer"
                    if parent_node.level > 0
                    else f"{parent_uri}/ca_certificate.cer"
                )

                ext["extn_value"][0]["access_location"] = parent_cert_url

                ext["extn_value"].append({
                    "access_method": "ca_issuers",
                    "access_location": parent_cert_url
                })

        with open(node.json_config_path, "w") as f:
            json.dump(data, f, indent=2)


    def create_children(p_node):
        if p_node.level >= depth - 1: return
        for _ in range(branching_factor):
            child = RPKINode(level=p_node.level + 1, parent=p_node)
            p_node.children.append(child)
            mutate_ca_config(child, p_node)
            all_nodes.append(child)
            create_children(child)

    mutate_ca_config(root)
    create_children(root)
    
    for node in all_nodes:
        node.mft_ee_json = os.path.join(tmp_dir, f"mft_L{node.level}_{node.name}.json")
        shutil.copy(mft_template, node.mft_ee_json)
        sync_ee_json(node.mft_ee_json, node.name, node.ski, f"{node.uri}/revoked.crl", f"{node.uri}/manifest.mft")
        
        if not node.children: 
            node.roa_ee_json = os.path.join(tmp_dir, f"roa_L{node.level}_{node.name}.json")
            shutil.copy(roa_template, node.roa_ee_json)
            sync_ee_json(node.roa_ee_json, node.name, node.ski, f"{node.uri}/revoked.crl", f"{node.uri}/test_roa.roa")
            
    return all_nodes, root

if __name__ == '__main__':

    TREE_DEPTH = 2           # TA -> SubL1 -> SubL2
    BRANCH_FACTOR = 1        # 
    BASE_REPO = "./my_repo/"
    TMP_CONFIG_DIR = "./mutation/data/data/tmp_configs/"
    
    os.system(f"rm -rf {BASE_REPO} ../local_repo ../FORT_LOCAL {TMP_CONFIG_DIR}")
    os.system("rm -rf ../rpki-client_cache && mkdir ../rpki-client_cache")
    os.system("rm -rf ../octorpki_cache && mkdir ../octorpki_cache")
    os.makedirs(os.path.join(BASE_REPO, "ca_certificate"), exist_ok=True)
    os.makedirs(os.path.join(BASE_REPO, "key"), exist_ok=True)
    os.makedirs(os.path.join(BASE_REPO, "tal"), exist_ok=True)
    os.makedirs(TMP_CONFIG_DIR, exist_ok=True)

    all_nodes, root_node = build_topology(
        depth=TREE_DEPTH,
        branching_factor=BRANCH_FACTOR,
        ta_template="./mutation/data/data/ca_certificate_mutate.json",
        sub_template="./mutation/data/data/ca_certificate/sub_ca_mutate.json",
        mft_template="./mutation/data/data/ca_certificate/manifest.json",
        roa_template="./mutation/data/data/ca_certificate/sub_ca/roa_mutate.json",
        tmp_dir=TMP_CONFIG_DIR
    )

    Log.success(f"\n==================== STARTING {TREE_DEPTH} LAYER BRANCHING FUZZER ====================")
    Log.info(f"Total Nodes to Build: {len(all_nodes)}")

    Log.info("[Phase 1] Building Certificates...")
    for node in all_nodes:
        is_ta = (node.level == 0)
        
        if is_ta:
            node.physical_dir = BASE_REPO
            node.cert_path = os.path.join(BASE_REPO, "ca_certificate.cer")
        else:
            node.physical_dir = os.path.join(node.parent.physical_dir, node.name)
            
            node.cert_path = os.path.join(node.parent.physical_dir, f"{node.name}.cer")
        
        os.makedirs(node.physical_dir, exist_ok=True)
        node.priv_key_path = os.path.join(BASE_REPO, "key", f"key_L{node.level}_{node.name}.pem")
        
        p_priv = None
        if node.parent:
            p_priv = serialization.load_pem_private_key(open(node.parent.priv_key_path, 'rb').read(), None, default_backend())
        
        ca_config = certParser(json_data=json.load(open(node.json_config_path, "r"))).parser_cacert()
        build_ca(issuer_private_key=p_priv, ca_path=node.cert_path, 
                 config=ca_config, key_export_path=node.priv_key_path, is_ta=is_ta)

    Log.info("[Phase 2] Building Signed Objects...")
    for node in all_nodes:
        if node.level == 0:
            export_tal(node.cert_path, os.path.join(BASE_REPO, "tal/ta.tal"))

        crl_path = os.path.join(node.physical_dir, "revoked.crl")
        crl_config = CRLConfig(
            version=1, 
            signature=signatureAlgorithmConfig(oid='1.2.840.113549.1.1.11', parameters=None),
            issuer=node.name, 
            this_update="20241125055723Z", 
            next_update="20301125055723Z",
            crl_number=CrlNumConfig(0, False), 
            aki_critical=False, 
            revoked_certificates=None
        )
        build_crl(issuer_private_key_path=node.priv_key_path, config=crl_config, crl_path=crl_path)

        mft_files = [crl_path]
        for child in node.children:
            mft_files.append(child.cert_path)
            
        if not node.children:
            roa_path = os.path.join(node.physical_dir, "test_roa.roa")
            roa_ee_data = json.load(open(node.roa_ee_json, "r"))["content"]["certificates"][0]
            roa_config = ROAConfig()
            roa_config.ee_config = eeCertParser(json_data=roa_ee_data).parse_eecert()
            build_roa(issuer_private_key_path=node.priv_key_path, roa_config=roa_config, roa_path=roa_path)
            mft_files.append(roa_path)

        mft_path = os.path.join(node.physical_dir, "manifest.mft")
        mft_config = MFTConfig()
        mft_config.file_names = mft_files
        mft_ee_data = json.load(open(node.mft_ee_json, "r"))["content"]["certificates"][0]
        mft_config.ee_config = eeCertParser(json_data=mft_ee_data).parse_eecert()
        build_mft(issuer_private_key_path=node.priv_key_path, mft_config=mft_config, mft_path=mft_path)

    cache_base = "./my_repo/rsync/localhost/8080/myrpki"
    os.makedirs(cache_base, exist_ok=True)
    
    for item in os.listdir(BASE_REPO):
        if item in ["key", "tal", "ca_certificate"]: continue
        src = os.path.join(BASE_REPO, item)
        dst = os.path.join(cache_base, item)
        if os.path.isdir(src): shutil.copytree(src, dst, dirs_exist_ok=True)
        else: shutil.copy2(src, dst)

    shutil.copy2(root_node.cert_path, cache_base)
    
    Log.success("\n" + "="*20 + " RUNNING Routinator " + "="*20)
    
    routinator_cmd = "RP/routinator --allow-dubious-hosts --repository-dir ./my_repo/my_repo/tal --fresh --strict --disable-rrdp --unsafe-vrps reject --stale reject -vvv vrps"
    #start_time = time.time()
    os.system(f"{routinator_cmd} 2>&1")
    #end_time = time.time()
    #duration = end_time - start_time
    #print(f"Routinator : {duration:.4f}s")
    Log.success("\n" + "="*20 + " RUNNING Fort  " + "="*20)

    fort_cmd = "RP/fort --mode=standalone --tal=./my_repo/tal --local-repository=./my_repo
    #start_time = time.time()
    os.system(f"{fort_cmd} 2>&1")
    #end_time = time.time()
    #duration = end_time - start_time
    #print(f"Fort : {duration:.4f}s")
    
    Log.success("\n" + "="*20 + " RUNNING Octorpki  " + "="*20)
    octo_cmd = "RP/octorpki -mode oneoff -tal.root './my_repo/tal/ta.tal' -tal.name 'rfuzz_root' -cache '../local_repo/rsync' -output.roa './test/octorpki_output.json' -output.sign=false -rrdp=false -loglevel error"

    #start_time = time.time()
    os.system(octo_cmd)
    #end_time = time.time()
    #duration = end_time - start_time
    #print(f"Octorpki : {duration:.4f}s")
    
    if os.path.exists("test/octorpki_output.json"):
        with open("test/octorpki_output.json", 'r') as f:
            data = json.load(f)
            Log.info(data)

    os.system("chmod -R 777 ../local_repo && chmod -R 777 ./test")
    Log.success("\n" + "="*20 + " RUNNING RPKI Client  " + "="*20)
    rpki_client = "RP/rpki-client -t ./my_repo/tal/ta.tal -d ../local_repo/ -v ./test"
    #start_time = time.time()
    os.system(rpki_client)
    #end_time = time.time()
    #duration = end_time - start_time
    #print(f"Rpki Client : {duration:.4f}s")"""