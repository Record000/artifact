from rpki.cert.CertParser import parse_cert, certParser
from rpki.cert.TACert import TACertificateBuilder
from rpki.cert.config import TACertConfig

import os

def list_all_files(base_dir):
    file_list = []
    
    for root, _, files in os.walk(base_dir):
        for file in files:
            file_list.append(os.path.join(root, file))  

    return file_list

def rebuild_cert(file_path):
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

    config = TACertConfig(
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

    builder = TACertificateBuilder(config, debug=False)
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

target_dir = "./mutation/test/cert_json"
#  ./mutation/test/cert_json/ripe-ncc/DEFAULT/QYbmudH3jJTWP6yTSrmq3AyW1D4.json

if not os.path.exists(target_dir):
    os.makedirs(target_dir)

all_files = list_all_files(target_dir)
cert_file = [x for x in all_files if x.endswith(".json")]

error_files = 0
correct_files = 0
current = 0
print("Total files: ", len(cert_file))
for file in cert_file:
    current += 1
    print("Current: ", current)
    try:
        # parse_cert(file)
        rebuild_cert(file)
        correct_files += 1
    except Exception as e:
        error_files += 1
        print("Error: ", file)
        print(e)
print(error_files)
print(correct_files)
# file_path = './mutation/test/cert_json/ripe-ncc/DEFAULT/U1glzov1RBcCgvcgokhBQVaLDn0.json'
# # ./mutation/test/cert_json/ripe-ncc/DEFAULT/XfQO50ielcV_EEJxkZ2iaLxRP5s.json
# # ./mutation/test/cert_json/ripe-ncc/aca/KpSo3VVK5wEHIJnHC2QHVV3d5mk.json
# # parse_cert("./mutation/test/cert_json/ripe-ncc/DEFAULT/XfQO50ielcV_EEJxkZ2iaLxRP5s.json", "./mutation/test/cert_json/ripe-ncc/DEFAULT/U1glzov1RBcCgvcgokhBQVaLDn0.json")


# config = TACertConfig(
#     version=version,
#     serial_number=serial_number,
#     signature_algorithm=signature,
#     issuer=issuer,
#     validityconfig=validaty,
#     subject=subject,
#     basic_constraints=basic_constraints,
#     key_identifier_critical=key_identifier,
#     key_usage=key_usage,
#     subject_information_access=subject_information_access,
#     ip_address=ipaddr_blocks,
#     as_id=asnum_blocks,
#     certificate_policies=certificate_policy
# )

# builder = TACertificateBuilder(config, debug=False)
# builder.set_version()
# builder.set_serial_number()
# builder.set_signature_algorithm()
# builder.set_issuer()
# builder.set_validity()
# builder.set_subject()
# builder.set_subjectPublicKeyInfo()
# builder.set_issuer_unique_id()
# builder.set_subject_unique_id()
# builder.basic_constraints_extension()
# builder.key_identifier_extension()
# builder.key_usage_extension()
# builder.subject_information_access_extension()
# builder.certificate_policies_extension()
# builder.ip_address_extension()
# builder.as_id_extension()

# builder.build_certificate()

# builder.export_certificate("./test_rebuild.cer")

# # print(cert_parser.version())
# # print(cert_parser.serial_number())
# # print(cert_parser.signature())
# # print(cert_parser.issuer())
# # print(cert_parser.validaty())
# # print(cert_parser.subject())
# # print(cert_parser.spki_algorithm())
# # print(cert_parser.certificate_policy())
# # print(cert_parser.basic_constraints())
# # print(cert_parser.key_usage())
# # print(cert_parser.key_identifier())
# # print(cert_parser.subject_information_access())
# # print(cert_parser.ipaddr_blocks())
# # print(cert_parser.asnum_blocks())