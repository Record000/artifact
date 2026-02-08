from datetime import datetime

class signatureAlgorithmConfig:
    def __init__(self, oid='1.2.840.113549.1.1.11', 
                 parameters=None):
        self.oid = oid
        self.parameters = parameters
    
    def __str__(self):
        return str({"algorithm": self.oid, "parameters": self.parameters})

class RevokeCertConfig:
    def __init__(self, user_certificate, revocation_date, crl_entry_extensions=None):
        self.user_certificate = user_certificate
        self.revocation_date = revocation_date
        self.crl_entry_extensions = crl_entry_extensions

    def __str__(self):
        return f"User Certificate: {self.user_certificate}, Revocation Date: {self.revocation_date}, CRL Entry Extensions: {self.crl_entry_extensions}"

class CrlNumConfig:
    def __init__(self, crl_number:int=None, critical:bool=None):
        self.crl_number = crl_number
        self.critical = critical
        
    def __str__(self):
        return f"CRL Number: {str(self.crl_number)}, Critical: {self.critical}"

class CRLConfig:
    def __init__(self, version:int=None, signature:signatureAlgorithmConfig=None,
                 issuer:str=None, this_update:datetime=None, next_update:datetime=None,
                 crl_number:CrlNumConfig=None, aki_critical:bool=None,
                 revoked_certificates:list[RevokeCertConfig]=None):
        self.version = version # 1
        self.signature_algorithm = signature #"1.2.840.113549.1.1.11"
        self.issuer = issuer # "ca_certificate"
        self.this_update = this_update # datetime.strptime('2024-11-25T05:57:23+00:00', "%Y-%m-%dT%H:%M:%S+00:00")
        self.next_update = next_update # datetime.strptime('2025-12-02T05:57:23+00:00', "%Y-%m-%dT%H:%M:%S+00:00")
        self.crl_number = crl_number #0
        self.aki_critical = aki_critical # False
        self.revoked_certificates = revoked_certificates 
        
