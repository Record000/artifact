from CACert import CACertificateBuilder
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

builder = CACertificateBuilder()
builder.set_version(2)
builder.set_serial_number(2)
builder.set_signature_algorithm()
builder.set_issuer('ca_certificate')
builder.set_validity('20241125055723Z', '20301125055723Z')
builder.set_subject('sub_ca')
builder.set_subjectPublicKeyInfo()
builder.set_issuer_unique_id()
builder.set_subject_unique_id()
builder.basic_constraints_extension()
builder.key_identifier_extension()
issuer_rsa_key_path = "./my_repo/key/ta_public_key.pem"
with open(issuer_rsa_key_path, 'rb') as f:
    issuer_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
builder.authority_key_identifier_extension(critical=False, issuer_public_key=issuer_public_key) # remains to be fixed
builder.key_usage_extension()
builder.crl_distribution_points_extension(critical=False, crl_uri='rsync://localhost:8080/myrpki/ca_certificate/revoked.crl')
builder.authority_information_access_extension(critical=False, ca_issuer_uri='rsync://localhost:8080/myrpki/ca_certificate.cer')
builder.subject_information_access_extension(critical=False, ca_uri="rsync://localhost:8080/myrpki/ca_certificate/sub_ca",
                                             mft_uri="rsync://localhost:8080/myrpki/ca_certificate/sub_ca/manifest.mft",)
builder.certificate_policies_extension()
builder.ip_address_extension(critical=True, ipv4_address=['0.0.0.0/8'], ipv6_address=['::/8'])
builder.as_id_extension(critical=True, as_min=65010, as_max=65019)
issuer_private_key = serialization.load_pem_private_key(open("./my_repo/key/ta_private_key.pem", 'rb').read(), password=None, backend=default_backend())
builder.build_certificate(issuer_private_key=issuer_private_key)
import os
if not os.path.exists('./my_repo/ca_certificate'):
    os.makedirs('./my_repo/ca_certificate')
builder.export_certificate('./my_repo/ca_certificate/sub_ca.cer')
builder.export_private_key('./my_repo/key/sub_ca_private_key.pem')
builder.export_public_key('./my_repo/key/sub_ca_public_key.pem')