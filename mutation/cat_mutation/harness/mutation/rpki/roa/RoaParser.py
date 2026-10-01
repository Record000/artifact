from .config import ROAConfig, signatureAlgorithmConfig
from ..cert.EECert import EECertConfig
import json
from datetime import datetime
import os
from tqdm import tqdm

class roaParser:
    
    def __init__(self, json_data=None, json_path=None):
        if json_path is None and json_data is None:
            raise ValueError("Either json_data or json_path should be provided")
        if json_data is None:
            self.json_data = json.load(open(json_path))
        else:
            self.json_data = json_data
        
        self.json_data = self.json_data["content"]

    def print_roa_data(self):
        print("ROA Data: ", self.json_data)
        
    def version(self):
        return self.json_data["version"]
    
    def digest_algorithms(self):
        return self.json_data["digest_algorithms"]
    
    def encap_content_info(self):
        return self.json_data["encap_content_info"]
    
    def eecerts(self):
        pass
    

def list_all_files(base_dir):
    file_list = []
    
    for root, _, files in os.walk(base_dir):
        for file in files:
            file_list.append(os.path.join(root, file))  

    return file_list

if __name__ == '__main__':
    # json_path="./mutation/test/roa_json/afrinic/member_repository/F36A0B3B/EC692812DFA311EFA7A90C4E762E951A/8500AAA4DFA511EFA4A0995A762E951A.json"
    # parser = roaParser(json_path=json_path)
    # parser.print_roa_data()
    # parser.digest_algorithms()
    
    # target_dir = "./mutation/test/crl_json"
    # all_files = list_all_files(target_dir)
    # crl_json_files = [x for x in all_files if x.endswith(".json")]
    # max_revokes = -1
    # max_revokes_file = None
    # for json_file in tqdm(crl_json_files):
    #     parser = crlParser(json_path=json_file)
    #     try:
    #         parser.parse_crl()
    #         crl_extensions_num = parser.crl_extensions_num()
    #         if crl_extensions_num != 2:
    #             print("CRL Extensions Number not 2: ", json_file)
    #         revokes_num = len(parser.revoke_certificates())
    #         if revokes_num > max_revokes:
    #             max_revokes = revokes_num
    #             max_revokes_file = json_file
    #     except Exception as e:
    #         print("Error: ", json_file, e)
    #         continue
    # print("Max Revokes: ", max_revokes)
    # print("json_file: ", max_revokes_file)
    
    target_dir = "./mutation/test/roa_json"
    all_files = list_all_files(target_dir)
    crl_json_files = [x for x in all_files if x.endswith(".json")]
    for json_file in tqdm(crl_json_files):
        parser = roaParser(json_path=json_file)
        digest_algorithms = parser.digest_algorithms()
        if len(digest_algorithms) != 1:
            raise ValueError("Digest Algorithms not 1: ", json_file)
        if digest_algorithms[0]["algorithm"] != "sha256":
            raise ValueError("Digest Algorithm not sha256: ", json_file)
        # try:
        #     parser.parse_crl()
        #     crl_extensions_num = parser.crl_extensions_num()
        #     if crl_extensions_num != 2:
        #         print("CRL Extensions Number not 2: ", json_file)
        #     revokes_num = len(parser.revoke_certificates())
        #     if revokes_num > max_revokes:
        #         max_revokes = revokes_num
        #         max_revokes_file = json_file
        # except Exception as e:
        #     print("Error: ", json_file, e)
            # continue