from rpki.cert.TACert import CACertificateBuilder
from rpki.crl.crl import CRLBuilder, CRLConfig, RevokeCertConfig, CrlNumConfig
from rpki.mft.mft import RPKIManifest, MFTConfig
from rpki.cert.EECert import EECertConfig
from rpki.roa.roa import ROABuilder, ROAConfig
import base64
from rpki.mutator.CertMutator import CertMutator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from rpki.xml.notification import NotificationXml
from rpki.xml.snapshot import SnapshotXml
from rpki.xml.delta import DeltaXml
import os
import subprocess
from rpki.logger.logger import logger
import json
import uuid
from rpki.cert.CertParser import certParser, eeCertParser
from rpki.cert.config import CACertConfig, signatureAlgorithmConfig, validityConfig, basicConstraintsConfig, keyUsageConfig, \
    crlConfig, siaConfig, aiaConfig, certpoliciesConfig, ipaddrsConfig, asidConfig, keyUsage, asid, asidRange, ipv4addr, ipv6addr, \
    ipv4AddrRange, ipv6AddrRange

def build_tal(ca_path, export_path):
    with open(ca_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    # print(cert)
    public_key_info_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # print(public_key_info_der)
    tal_contents = f"rsync://localhost:8080/myrpki/ca_certificate.cer\n\n".encode()
    tal_contents += base64.b64encode(public_key_info_der)

    if os.path.exists("./my_repo/tal") is False:
        os.mkdir("./my_repo/tal")
    with open(export_path, "wb") as tal_file:
        tal_file.write(tal_contents)
    print("TAL exported to "+export_path)

def build_ca(issuer_private_key, ca_path, config:CACertConfig, key_export_path, mutator:list[CertMutator]=None, rsa_key_path=None):
    # TA's issuer_private_key is None
    is_ta = False
    if issuer_private_key is None:
        print("Building TA Certificate")
        is_ta = True
    builder = CACertificateBuilder(config=config, debug=False,mutator=mutator)
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
    if is_ta is False:
        builder.authority_key_identifier_extension(issuer_public_key=issuer_private_key.public_key())
    builder.key_usage_extension()
    if is_ta is False:
        builder.crl_distribution_points_extension()
        builder.authority_information_access_extension()
    builder.subject_information_access_extension()
    builder.certificate_policies_extension()
    builder.ip_address_extension()
    builder.as_id_extension()
    builder.build_certificate(issuer_private_key=issuer_private_key)
    builder.export_certificate(ca_path)

    if os.path.exists("./my_repo/key") is False:
        os.mkdir("./my_repo/key")
    builder.export_private_key(key_export_path)
    print("Private key exported to "+key_export_path)
    
    if is_ta:
        build_tal(ca_path=ca_path, export_path="./my_repo/tal/ta.tal")

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

def run_script(script_path):
    try:
        process = subprocess.Popen(
            ["bash", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        for line in process.stdout:
            logger.info(line.strip())

        return_code = process.wait()
        if return_code != 0:
            logger.error(f"error in :{return_code}")
        else:
            logger.info("succrss")
    except Exception as e:
        logger.exception(f"error: {e}")

if __name__ == '__main__':
    base_dir = "./my_repo/"
    if os.path.exists(base_dir) is False:
        os.makedirs(base_dir)


    # 1. Build TA
    ta_private_key_path = "./my_repo/key/ta_private_key.pem"

    data_tmp = json.load(open("./mutation/data/data/ca_certificate.json", "r"))
    config = certParser(json_data=data_tmp).parser_cacert()
    build_ca(issuer_private_key=None, ca_path="./my_repo/ca_certificate.cer", config=config,
             key_export_path=ta_private_key_path,mutator=None,rsa_key_path="./my_repo/key/ta_private_key.pem")
    
    # 6. Build Subca ROA
    issuer_rsa_key_path = "./my_repo/key/ta_private_key.pem"
    roa_path = "./my_repo/ca_certificate/test_roa.roa"
    roa_config = ROAConfig()
    roa_config.ee_config =eeCertParser(json_data=json.load(open("./mutation/data/data/ca_certificate/roa.json", "r"))["content"]["certificates"][0]).parse_eecert()
    roa_config.ee_config.need_asid = False
    roa_config.ee_config.is_mft = False
    build_roa(issuer_private_key_path=issuer_rsa_key_path,roa_config=roa_config,roa_path=roa_path)


    # 3. Build CRL
    crl_path="./my_repo/ca_certificate/revoked.crl"
    crl_config = CRLConfig(version=1, signature=signatureAlgorithmConfig(oid='1.2.840.113549.1.1.11', parameters=None),
                                issuer="cacertificate", this_update="20241125055723Z", next_update="20301125055723Z",
                                crl_number=CrlNumConfig(0, False), aki_critical=False, revoked_certificates=None)
    build_crl(issuer_private_key_path=ta_private_key_path, config=crl_config,
              crl_path=crl_path)


    # 4. Build Manifest
    file_names = ["./my_repo/ca_certificate/revoked.crl",
            "./my_repo/ca_certificate/test_roa.roa"]
    mft_path = "./my_repo/ca_certificate/manifest.mft"
    mft_config = MFTConfig()
    mft_config.file_names = file_names
    # get config from ./mutation/data/data/ca_certificate/manifest.json 
    data_tmp = json.load(open("./mutation/data/data/ca_certificate/manifest.json", "r"))["content"]["certificates"][0]
    ee_cert_config = eeCertParser(json_data=data_tmp).parse_eecert()
    mft_config.ee_config = ee_cert_config
    build_mft(issuer_private_key_path=ta_private_key_path, 
              mft_config=mft_config,
              mft_path=mft_path)

