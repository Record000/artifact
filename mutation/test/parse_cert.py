from rpki.cert.CertParser import parse_cert, certParser

import os

def list_all_files(base_dir):
    file_list = []
    
    for root, _, files in os.walk(base_dir):
        for file in files:
            file_list.append(os.path.join(root, file)) 

    return file_list

target_dir = "./mutation/test/cert_json"
#  ./mutation/test/cert_json/ripe-ncc/DEFAULT/QYbmudH3jJTWP6yTSrmq3AyW1D4.json


if not os.path.exists(target_dir):
    os.makedirs(target_dir)

all_files = list_all_files(target_dir)
cert_file = [x for x in all_files if x.endswith(".json")]

error_files = 0

for file in cert_file[0:20]:
    try:
        parse_cert(file)
    except Exception as e:
        error_files += 1
        print("Error: ", file)
        print(e)
print(error_files)
file_path = './mutation/test/cert_json/ripe-ncc/DEFAULT/U1glzov1RBcCgvcgokhBQVaLDn0.json'
# ./mutation/test/cert_json/ripe-ncc/DEFAULT/XfQO50ielcV_EEJxkZ2iaLxRP5s.json
# ./mutation/test/cert_json/ripe-ncc/aca/KpSo3VVK5wEHIJnHC2QHVV3d5mk.json
# parse_cert("./mutation/test/cert_json/ripe-ncc/DEFAULT/XfQO50ielcV_EEJxkZ2iaLxRP5s.json", "./mutation/test/cert_json/ripe-ncc/DEFAULT/U1glzov1RBcCgvcgokhBQVaLDn0.json")
cert_parser = certParser(file_path)
print(cert_parser.version())
print(cert_parser.serial_number())
print(cert_parser.signature())
print(cert_parser.issuer())
print(cert_parser.validaty())
print(cert_parser.subject())
print(cert_parser.spki_algorithm())
print(cert_parser.certificate_policy())
print(cert_parser.basic_constraints())
print(cert_parser.key_usage())
print(cert_parser.key_identifier())
print(cert_parser.subject_information_access())
print(cert_parser.ipaddr_blocks())
print(cert_parser.asnum_blocks())