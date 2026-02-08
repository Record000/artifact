from rpki.crl.crl import CRLBuilder
from rpki.crl.config import CRLConfig, RevokeCertConfig
from rpki.crl.CrlParser import crlParser
from datetime import datetime
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm

issuer_private_key_path="./my_repo/key/sub_ca_private_key.pem"

issuer_private_key_path = issuer_private_key_path
issuer_private_key = serialization.load_pem_private_key(open(issuer_private_key_path, 'rb').read(),
                                                        password=None, backend=default_backend())



# json_path="./mutation/test/crl_json/afrinic/04E8B0D80F4D11E0B657D8931367AE7D/62gPOPXWxxu0sQa4vQZYUBLaMbY.json"
# parser = crlParser(json_path=json_path)
# crl_config = parser.parse_crl()

# test_crl = CRLBuilder(issuer_private_key=issuer_private_key, config=crl_config)

# test_crl.set_version()
# test_crl.set_signature_algorithm()
# test_crl.set_issuer()
# test_crl.set_this_update()
# test_crl.set_next_update()
# test_crl.set_revoke_certificates()
# test_crl.authority_key_identifier_extension()
# test_crl.crl_number_extension()
# crl = test_crl.build_crl()
# test_crl.export_crl('./test.crl')
def list_all_files(base_dir):
    file_list = []
    
    for root, _, files in os.walk(base_dir):
        for file in files:
            file_list.append(os.path.join(root, file))  

    return file_list
target_dir = "./mutation/test/crl_json"
all_files = list_all_files(target_dir)
crl_json_files = [x for x in all_files if x.endswith(".json")]
for json_file in tqdm(crl_json_files):
    parser = crlParser(json_path=json_file)
    try:
        config = parser.parse_crl()
        test_crl = CRLBuilder(issuer_private_key=issuer_private_key, config=config)
        test_crl.set_version()
        test_crl.set_signature_algorithm()
        test_crl.set_issuer()
        test_crl.set_this_update()
        test_crl.set_next_update()
        test_crl.set_revoke_certificates()
        test_crl.authority_key_identifier_extension()
        test_crl.crl_number_extension()
        crl = test_crl.build_crl()
        test_crl.export_crl('./test.crl')
    except Exception as e:
        print("Error: ", json_file, e)
        continue