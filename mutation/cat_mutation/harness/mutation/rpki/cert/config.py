class signatureAlgorithmConfig:
    def __init__(self, oid='1.2.840.113549.1.1.11', 
                 parameters=None):
        self.oid = oid
        self.parameters = parameters
    
    def __str__(self):
        return str({"algorithm": self.oid, "parameters": self.parameters})

def iso8601_to_generalized(iso_time):
    from datetime import datetime
    dt = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
    return dt.strftime("%Y%m%d%H%M%SZ")
    
def is_iso8601_pyiso8601(s):
    import iso8601
    try:
        iso8601.parse_date(s)
        return True
    except iso8601.ParseError:
        return False

class validityConfig:
    def __init__(self, not_before="20241125055723Z", not_after="20301125055723Z"):
        if is_iso8601_pyiso8601(not_before):
            not_before = iso8601_to_generalized(not_before)
        if is_iso8601_pyiso8601(not_after):
            not_after = iso8601_to_generalized(not_after)
        self.not_before = not_before
        self.not_after = not_after
        
    def __str__(self):
        return str({"not_before": self.not_before, "not_after": self.not_after})

class basicConstraintsConfig:
    
    def __init__(self, critical=True, ca=True, path_length=None):
        self.critical = critical
        self.ca = ca
        self.path_length = path_length
        
    def __str__(self):
        return str({"critical": self.critical, "ca": self.ca, "path_length": self.path_length})

class keyUsage:
    def __init__(self):
        self.digital_signature = False
        self.content_commitment = False
        self.key_encipherment = False
        self.data_encipherment = False
        self.key_agreement = False
        self.key_cert_sign = False
        self.crl_sign = False
        self.encipher_only = False
        self.decipher_only = False     
    
    def list_init(self, key_usage:list):
        for key in key_usage:
            if key == "digital_signature":
                self.digital_signature = True
            elif key == "content_commitment":
                self.content_commitment = True
            elif key == "key_encipherment":
                self.key_encipherment = True
            elif key == "data_encipherment":
                self.data_encipherment = True
            elif key == "key_agreement":
                self.key_agreement = True
            elif key == "key_cert_sign":
                self.key_cert_sign = True
            elif key == "crl_sign":
                self.crl_sign = True
            elif key == "encipher_only":
                self.encipher_only = True
            elif key == "decipher_only":
                self.decipher_only = True
            else:
                exit("Unknown key: ",
                     key)
        
    def keyUsageBitString(self):
        bitstring = ""
        if self.digital_signature:
            bitstring += "1"
        else:
            bitstring += "0"
        if self.content_commitment:
            bitstring += "1"
        else:
            bitstring += "0"
        if self.key_encipherment:
            bitstring += "1"
        else:
            bitstring += "0"
        if self.data_encipherment:
            bitstring += "1"
        else:
            bitstring += "0"
        if self.key_agreement:
            bitstring += "1"
        else:
            bitstring += "0"
        if self.key_cert_sign:
            bitstring += "1"
        else:
            bitstring += "0"
        if self.crl_sign:
            bitstring += "1"
        else:
            bitstring += "0"
        if self.encipher_only:
            bitstring += "1"
        else:
            bitstring += "0"
        if self.decipher_only:
            bitstring += "1"
        else:
            bitstring += "0"
        return bitstring

class keyUsageConfig:
    def __init__(self, critical, key_usage: keyUsage):
        self.critical = critical
        self.key_usage = key_usage
        self.keyUsageBits = key_usage.keyUsageBitString()
        
    def __str__(self):
        used = []
        for i in self.key_usage.__dict__.keys():
            if self.key_usage.__dict__[i] is True:
                used.append(i)
        return str({"critical": self.critical, "key_usage": used})

class crlConfig:
    def __init__(self, critical=False, crl_uris:list=None):
        self.critical = critical
        self.crl_uris = crl_uris
    
    def __str__(self):
        return str({"critical": self.critical, "crl_uris": self.crl_uris})

class siaConfig:
    def __init__(self, critical=False, accessed:list=None):
        self.critical = critical
        self.sia = {}
        for i in accessed:
            if i['access_method'] == 'ca_repository':
                self.sia["1.3.6.1.5.5.7.48.5"] = i['access_location']
            elif i['access_method'] == 'id-ad-rpkiManifest':
                self.sia["1.3.6.1.5.5.7.48.10"] = i['access_location']
            elif i['access_method'] == 'id-ad-rpkiNotify':
                self.sia["1.3.6.1.5.5.7.48.13"] = i['access_location']
            elif i['access_method'] == '1.3.6.1.5.5.7.48.11':
                self.sia["1.3.6.1.5.5.7.48.11"] = i['access_location']
            else:
                exit("Unknown access method: ", i['access_method'])
                
    def __str__(self):
        return str({"critical": self.critical, "sia": str(self.sia)})
        
class aiaConfig:
    def __init__(self, critical=False, ca_issuer_uri=None):
        self.critical = critical
        self.ca_issuer_uri = ca_issuer_uri

class certpoliciesConfig:
    def __init__(self, critical=False, policy_identifiers:list=None):
        self.critical = critical
        self.policy_identifiers = policy_identifiers
        
    def __str__(self):
        return str({"critical": self.critical, "policy_identifiers": str(self.policy_identifiers)})

class ipv4addr:
    def __init__(self, ipv4_addr):
        self.ipv4_addr = ipv4_addr
    def __str__(self):
        return str({"ipv4_addr": self.ipv4_addr})

class ipv4AddrRange:
    def __init__(self, min, max):
        self.min = min
        self.max = max
    def __str__(self):
        return str({"min": self.min, "max": self.max})

class ipv6addr:
    def __init__(self, ipv6_addr):
        self.ipv6_addr = ipv6_addr
    def __str__(self):
        return str({"ipv6_addr": self.ipv6_addr})

class ipv6AddrRange:
    def __init__(self, min, max):
        self.min = min
        self.max = max
    def __str__(self):
        return str({"min": self.min, "max": self.max})
    
class ipaddrsConfig:
    def __init__(self, critical=True, ipv4_addrs:list=None, ipv6_addrs:list=None):
        self.critical = critical
        if ipv4_addrs is not None:
            for i in ipv4_addrs:
                if isinstance(i, ipv4addr) is False and isinstance(i, ipv4AddrRange) is False:
                    raise ValueError("Unknown ipv4addr type")
        if ipv6_addrs is not None:
            for i in ipv6_addrs:
                if isinstance(i, ipv6addr) is False and isinstance(i, ipv6AddrRange) is False:
                    raise ValueError("Unknown ipv6addr type")
        self.ipv4_addrs = ipv4_addrs
        self.ipv6_addrs = ipv6_addrs
        
    def __str__(self):
        if self.ipv4_addrs is None:
            self.ipv4_addrs = []
        if self.ipv6_addrs is None:
            self.ipv6_addrs = []
        str_ipv4 = [str(i) for i in self.ipv4_addrs]
        str_ipv6 = [str(i) for i in self.ipv6_addrs]
        return str({"critical": self.critical, "ipv4_addrs": str(str_ipv4), "ipv6_addrs": str(str_ipv6)})

class asid:
    def __init__(self, asid):
        self.asid = asid
    def __str__(self):
        return str({"asid": self.asid})

class asidRange:
    def __init__(self, min, max):
        self.min = min
        self.max = max
    def __str__(self):
        return str({"min": self.min, "max": self.max})

class asidConfig:
    def __init__(self, critical=True, asids:list=None):
        for i in asids:
            if isinstance(i, asid) is False and isinstance(i, asidRange) is False:
                raise ValueError("Unknown asid type: " + str(type(i)))
        self.critical = critical
        self.asids = asids
        
    def __str__(self):
        if self.asids is None:
            self.asids = []
        asids_str = [str(i) for i in self.asids]
        return str({"critical": self.critical, "asids": str(asids_str)})

class CACertConfig:
    def __init__(self, version=2, serial_number=1, signature_algorithm:signatureAlgorithmConfig=None,
                 issuer='ca_certificate', validityconfig:validityConfig=None, subject='ca_certificate',
                 basic_constraints:basicConstraintsConfig=None, key_identifier_critical=None,json_file_path=None,
                 key_usage:keyUsageConfig=None, crl_distribution_points:crlConfig=None, aki_critical=None,
                 authority_information_access:aiaConfig=None, subject_information_access:siaConfig=None,
                 certificate_policies:certpoliciesConfig=None, ip_address:ipaddrsConfig=None, as_id:asidConfig=None):
        self.version = version
        self.serial_number = serial_number
        self.signature_algorithm = signature_algorithm
        self.issuer = issuer
        self.validity = validityconfig
        self.subject = subject
        self.basic_constraints = basic_constraints
        self.key_identifier_critical = key_identifier_critical
        self.aki_critical = aki_critical
        self.key_usage = key_usage
        self.crl_distribution_points = crl_distribution_points
        self.authority_information_access = authority_information_access
        self.subject_information_access = subject_information_access
        self.certificate_policies = certificate_policies
        self.ip_address = ip_address
        self.as_id = as_id
        self.json_file_path = json_file_path
        
class EECertConfig:
    def __init__(self, version=None, serial_number=None, signature_algorithm:signatureAlgorithmConfig=None,
                 issuer=None, validityconfig:validityConfig=None, subject=None, need_asid:bool=None,
                 key_identifier_critical=None,json_file_path=None,key_usage:keyUsageConfig=None, 
                 crl_distribution_points:crlConfig=None, aki_critical=None, is_mft:bool=None,
                 authority_information_access:aiaConfig=None, subject_information_access:siaConfig=None,
                 certificate_policies:certpoliciesConfig=None, ip_address:ipaddrsConfig=None):
        self.version = version
        self.serial_number = serial_number
        self.signature_algorithm = signature_algorithm
        self.issuer = issuer
        self.validity = validityconfig
        self.subject = subject
        self.key_identifier_critical = key_identifier_critical
        self.aki_critical = aki_critical
        self.key_usage = key_usage
        self.crl_distribution_points = crl_distribution_points
        self.authority_information_access = authority_information_access
        self.subject_information_access = subject_information_access
        self.certificate_policies = certificate_policies
        self.ip_address = ip_address
        self.json_file_path = json_file_path
        self.need_asid = True
        self.is_mft = is_mft
        
# class EECertConfig:
#     def __init__(self, version:int=None, serial_number:int=None, signature_algorithm:str=None,
#                  issuer:str=None, validity:tuple=None, subject:str=None, key_identifier_critical:bool=None,
#                  authority_key_identifier_critical:bool=None, crl_critical:bool=None, crl_uri:str=None,
#                  aia_critical:bool=None, ca_issuer_uri:str=None, sia_critical:bool=None, sia_uri:str=None,
#                  certificate_policies_critical:bool=None, policy_identifier:str=None, ip_address_critical:bool=None,
#                  as_id_critical:bool=None, key_usage_critical:bool=None, ipv4_address:ipaddrsConfig=None,
#                  ipv6_address:ipaddrsConfig=None, need_asid:bool=None, is_mft:bool=None):
#         self.version = 2
#         self.serial_number = 1
#         self.signature_algorithm = '1.2.840.113549.1.1.11' # sha256WithRSAEncryption
#         self.issuer = 'ca_certificate'
#         self.validity = ('20241125055723Z', '20301125055723Z')
#         self.subject = 'ee_test'
#         self.key_identifier_critical = False
#         self.authority_key_identifier_critical = False
#         self.crl_critical = False
#         self.crl_uri = "rsync://localhost:8080/myrpki/ca_certificate/revoked.crl"
#         self.aia_critical = False
#         self.ca_issuer_uri = "rsync://localhost:8080/myrpki/ca_certificate.cer"
#         self.sia_critical = False
#         self.sia_uri = "rsync://localhost:8080/myrpki/ca_certificate/manifest.mft"
#         self.certificate_policies_critical = True
#         self.policy_identifier = '1.3.6.1.5.5.7.14.2'
#         self.ip_address_critical = True
#         self.as_id_critical = True
#         self.key_usage_critical = True
#         self.ipv4_address = None
#         self.ipv6_address = None
#         self.need_asid = True
#         self.is_mft = True