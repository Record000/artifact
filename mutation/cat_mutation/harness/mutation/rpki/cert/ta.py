from TACert import TACertificateBuilder
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509

builder = TACertificateBuilder()
builder.set_version(2)
builder.set_serial_number(1)
builder.set_signature_algorithm()
builder.set_issuer('ca_certificate')
builder.set_validity('20241125055723Z', '20301125055723Z')
builder.set_subject('ca_certificate')
builder.set_subjectPublicKeyInfo()
builder.set_issuer_unique_id()
builder.set_subject_unique_id()
builder.basic_constraints_extension()
builder.key_identifier_extension()
builder.key_usage_extension()
builder.subject_information_access_extension()
builder.certificate_policies_extension()
builder.ip_address_extension(critical=True, ipv4_address=['0.0.0.0/8'], ipv6_address=['::/8'])
builder.as_id_extension(critical=True, as_min=0, as_max=4294967295)
builder.build_certificate()
builder.export_certificate('./my_repo/ca_certificate.cer')
print("Certificate exported to ./my_repo/ca_certificate.cer")
import os
if os.path.exists("./my_repo/key") is False:
    os.mkdir("./my_repo/key")
builder.export_private_key('./my_repo/key/ta_private_key.pem')
print("Private key exported to ./my_repo/key/ta_private_key.pem")
builder.export_public_key('./my_repo/key/ta_public_key.pem')
print("Public key exported to ./my_repo/key/ta_public_key.pem")

with open("./my_repo/ca_certificate.cer", "rb") as cert_file:
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
import os
if os.path.exists("./my_repo/tal") is False:
    os.mkdir("./my_repo/tal")
with open("./my_repo/tal/ta.tal", "wb") as tal_file:
    tal_file.write(tal_contents)
print("TAL exported to ./my_repo/tal/ta.tal")
