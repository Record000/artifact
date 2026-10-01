from .config import CRLConfig, RevokeCertConfig, CrlNumConfig, signatureAlgorithmConfig
import json
from datetime import datetime
import os
from tqdm import tqdm

def utc2generalTime(time_str):

    dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))

    generalized_time = dt.strftime("%Y%m%d%H%M%SZ")
    return generalized_time

class crlParser:
    
    def __init__(self, json_data=None, json_path=None):
        if json_path is None and json_data is None:
            raise ValueError("Either json_data or json_path should be provided")
        if json_data is None:
            self.json_data = json.load(open(json_path))
        else:
            self.json_data = json_data
        self.tbs_cert_list = self.json_data['tbs_cert_list']
        self.tbs_cert_list['this_update'] = utc2generalTime(self.tbs_cert_list['this_update'])
        self.tbs_cert_list['next_update'] = utc2generalTime(self.tbs_cert_list['next_update'])
        for cert in self.tbs_cert_list['revoked_certificates']:
            cert['revocation_date'] = utc2generalTime(cert['revocation_date'])
        

    def print_crl_data(self):
        print("CRL Data: ", self.json_data)
        
    def version(self):
        return self.tbs_cert_list['version']
    
    def tbs_signature(self) -> signatureAlgorithmConfig:
        if self.tbs_cert_list['signature']['algorithm'] == "sha256_rsa":
            return signatureAlgorithmConfig(oid="1.2.840.113549.1.1.11")
        else:
            raise ValueError("New signature algorithm")
        
    def crl_signature(self) -> signatureAlgorithmConfig:
        if self.json_data["signature_algorithm"]["algorithm"] == "sha256_rsa":
            return signatureAlgorithmConfig(oid="1.2.840.113549.1.1.11")
        else:
            raise ValueError("New signature algorithm")
    
    def issuer(self):
        return self.tbs_cert_list['issuer']
    
    def this_update(self):
        this_update = self.tbs_cert_list['this_update']
        return this_update

    def next_update(self):
        next_update = self.tbs_cert_list['next_update']
        return next_update
    
    def revoke_certificates(self) -> list[RevokeCertConfig]:
        revoked_certificates = self.tbs_cert_list['revoked_certificates']
        certs = []
        for cert in revoked_certificates:
            crl_entry_extensions = cert['crl_entry_extensions']
            if crl_entry_extensions is not None:
                raise ValueError("CRL Entry Extensions not supported")
            certs.append(RevokeCertConfig(cert['user_certificate'], 
                                          cert['revocation_date']))
        return certs
    
    def crl_extensions_num(self):
        return len(self.tbs_cert_list['crl_extensions'])
    
    def crl_aki(self) -> bool:
        aki_index = -1
        for ext in self.tbs_cert_list['crl_extensions']:
            if ext['extn_id'] == "authority_key_identifier":
                aki_index = self.tbs_cert_list['crl_extensions'].index(ext)
                break
        if aki_index == -1:
            raise ValueError("Authority Key Identifier not found")
        aki_ext = self.tbs_cert_list['crl_extensions'][aki_index]
        if aki_ext["extn_value"]["authority_cert_issuer"] is not None:
            raise ValueError("Authority Cert Issuer not supported")
        if aki_ext["extn_value"]["authority_cert_serial_number"] is not None:
            raise ValueError("Authority Cert Serial Number not supported")
        return aki_ext['critical']
    
    def crl_number(self) -> CrlNumConfig:
        crl_number_index = -1
        for ext in self.tbs_cert_list['crl_extensions']:
            if ext['extn_id'] == "crl_number":
                crl_number_index = self.tbs_cert_list['crl_extensions'].index(ext)
                break
        if crl_number_index == -1:
            raise ValueError("CRL Number not found")
        crl_number_ext = self.tbs_cert_list['crl_extensions'][crl_number_index]
        return CrlNumConfig(crl_number_ext['extn_value'], crl_number_ext['critical'])
    
    def parse_crl(self):
        version = self.version()
        version = self.version().split("v")[-1]
        version = int(version) - 1
        tbs_signature = self.tbs_signature()
        issuer = self.issuer()
        this_update = self.this_update()
        next_update = self.next_update()
        revoke_certificates = self.revoke_certificates()
        crl_aki = self.crl_aki()
        crl_number = self.crl_number()
        config = CRLConfig(version=version, signature=tbs_signature,
                                issuer=issuer, this_update=this_update,
                                next_update=next_update, crl_number=crl_number,
                                aki_critical=crl_aki, revoked_certificates=revoke_certificates)
        return config

def list_all_files(base_dir):
    file_list = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            file_list.append(os.path.join(root, file))  

    return file_list

if __name__ == '__main__':
    # json_path="./mutation/test/crl_json/afrinic/04E8B0D80F4D11E0B657D8931367AE7D/62gPOPXWxxu0sQa4vQZYUBLaMbY.json"
    # parser = crlParser(json_path=json_path)
    # parser.parse_crl()
    
    target_dir = "./mutation/test/crl_json"
    all_files = list_all_files(target_dir)
    crl_json_files = [x for x in all_files if x.endswith(".json")]
    max_revokes = -1
    max_revokes_file = None
    for json_file in tqdm(crl_json_files):
        parser = crlParser(json_path=json_file)
        try:
            parser.parse_crl()
            crl_extensions_num = parser.crl_extensions_num()
            if crl_extensions_num != 2:
                print("CRL Extensions Number not 2: ", json_file)
            revokes_num = len(parser.revoke_certificates())
            if revokes_num > max_revokes:
                max_revokes = revokes_num
                max_revokes_file = json_file
        except Exception as e:
            print("Error: ", json_file, e)
            continue
    print("Max Revokes: ", max_revokes)
    print("json_file: ", max_revokes_file)