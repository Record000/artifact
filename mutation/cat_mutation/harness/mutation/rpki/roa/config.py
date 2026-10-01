from ..cert.EECert import EECertificateBuilder, EECertConfig

class signatureAlgorithmConfig:
    def __init__(self, oid='1.2.840.113549.1.1.11', 
                 parameters=None):
        self.oid = oid
        self.parameters = parameters
    
    def __str__(self):
        return str({"algorithm": self.oid, "parameters": self.parameters})

class ROAConfig:
    def __init__(self, ee_config=None):
        self.version = 'v3'
        self.digest_algorithm = '2.16.840.1.101.3.4.2.1'
        self.roaauthz_v = 0

        self.encap_content_info_content_type = "1.2.840.113549.1.9.16.1.24"
        self.ee_config = ee_config
        if self.ee_config is None: 
            self.ee_config = EECertConfig()