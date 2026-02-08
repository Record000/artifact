from rpki.cert.CertParser import parse_cert, eeCertParser
from rpki.cert.EECert import EECertificateBuilder
from rpki.cert.config import EECertConfig
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

issuer_private_key_path="./my_repo/key/sub_ca_private_key.pem"

issuer_private_key_path = issuer_private_key_path
issuer_private_key = serialization.load_pem_private_key(open(issuer_private_key_path, 'rb').read(),
                                                        password=None, backend=default_backend())

def list_all_files(base_dir):
    file_list = []
    
    for root, _, files in os.walk(base_dir):
        for file in files:
            file_list.append(os.path.join(root, file))  

    return file_list

def rebuild_eecert(file_path, is_mft = True):
    json_data = json.load(open(file_path, 'r'))
    json_data = json_data['content']["certificates"][0]
    cert_parser = eeCertParser(json_data=json_data)
    config = cert_parser.parse_eecert()
    if config.is_mft != is_mft:
        raise Exception("is_mft is not equal to the input value")
    builder = EECertificateBuilder(config=config, issuer_private_key=issuer_private_key)
    builder.set_version()
    builder.set_serial_number()
    builder.set_signature_algorithm()
    builder.set_issuer()
    builder.set_validity()
    builder.set_subject()
    builder.set_subjectPublicKeyInfo()
    builder.set_issuer_unique_id()
    builder.set_subject_unique_id()
    builder.key_identifier_extension()
    builder.authority_key_identifier_extension()
    builder.key_usage_extension()
    builder.crl_distribution_points_extension()
    builder.authority_information_access_extension()
    builder.certificate_policies_extension()
    builder.subject_information_access_extension()
    builder.as_id_extension()
    builder.ip_address_extension()
    builder.build_certificate()
    builder.export_certificate("./test_ee.cer")

    # version = cert_parser.version()
    # serial_number = cert_parser.serial_number()
    # signature = cert_parser.signature()
    # issuer = cert_parser.issuer()
    # validaty = cert_parser.validaty()
    # subject = cert_parser.subject()
    # spki_algorithm = cert_parser.spki_algorithm()
    # certificate_policy = cert_parser.certificate_policy()
    # basic_constraints = cert_parser.basic_constraints()
    # key_usage = cert_parser.key_usage()
    # key_identifier = cert_parser.key_identifier()
    # subject_information_access = cert_parser.subject_information_access()
    # ipaddr_blocks = cert_parser.ipaddr_blocks()
    # asnum_blocks = cert_parser.asnum_blocks()

    # config = EECertConfig(
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
    #     certificate_policies=certificate_policy,
    #     json_file_path=file_path
    # )

    # builder = EECertificateBuilder(config, debug=False)
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
    
    
# file_path = "./mutation/test/mft_json/afrinic/04E8B0D80F4D11E0B657D8931367AE7D/62gPOPXWxxu0sQa4vQZYUBLaMbY.json"
# rebuild_eecert(file_path)

is_mft = False
if is_mft:
    target_dir = "./mutation/test/mft_json"
else:
    target_dir = "./mutation/test/roa_json"
#  ./mutation/test/cert_json/ripe-ncc/DEFAULT/QYbmudH3jJTWP6yTSrmq3AyW1D4.json

if not os.path.exists(target_dir):
    os.makedirs(target_dir)

all_files = list_all_files(target_dir)
cert_file = [x for x in all_files if x.endswith(".json")]

error_files = 0
correct_files = 0
current = 0
print("Total files: ", len(cert_file))
from tqdm import tqdm
for file in tqdm(cert_file):
    current += 1
    # print("Current: ", current)
    # rebuild_eecert(file)
    try:
        # parse_cert(file)
        rebuild_eecert(file, is_mft=is_mft)
        correct_files += 1
    except Exception as e:
        error_files += 1
        print("Error: ", file)
        print(e)
print(error_files)
print(correct_files)


