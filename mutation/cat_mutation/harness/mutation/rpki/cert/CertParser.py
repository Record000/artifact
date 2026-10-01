import json
from .config import CACertConfig, signatureAlgorithmConfig, validityConfig, basicConstraintsConfig, keyUsageConfig, \
    crlConfig, siaConfig, aiaConfig, certpoliciesConfig, ipaddrsConfig, asidConfig, keyUsage, asid, asidRange, \
    ipv4AddrRange, ipv6AddrRange, ipv4addr, ipv6addr, EECertConfig

file_path = "./mutation/test/cert_json/afrinic/AfriNIC.json"

class certParser:
    def __init__(self, json_file=None, json_data=None, type="ca"):
        self.type = type
        if json_data is None:
            with open(json_file, "r") as f:
                self.data = json.load(f)
            self.tbs_cert = self.data['tbs_certificate']
            self.signature_algorithm = self.data['signature_algorithm']
        else:
            self.data = json_data
            self.tbs_cert = self.data['tbs_certificate']
            self.signature_algorithm = self.data['signature_algorithm']
        
    def version(self) -> str:
        return self.tbs_cert['version']
    
    def serial_number(self) -> int:
        return self.tbs_cert['serial_number']
    
    def signature(self) -> signatureAlgorithmConfig:
        '''
        "signature": { "algorithm": "sha256_rsa", "parameters": null }
        '''
        signature = self.tbs_cert["signature"]
        config = signatureAlgorithmConfig()
        if signature['algorithm'] == "sha256_rsa" or signature['algorithm'] == "rsa":
            config.oid = "1.2.840.113549.1.1.11"
            config.parameters = None
        else:
            exit("Find a new signature algorithm: ")
        
        return config
    
    def issuer(self) -> str:
        return self.tbs_cert['issuer']["common_name"]
    
    def validaty(self) -> validityConfig:
        config = validityConfig()
        not_before = self.tbs_cert['validity']['not_before']
        not_after = self.tbs_cert['validity']['not_after']
        config.not_before = not_before
        config.not_after = not_after
        return validityConfig(not_before, not_after)
    
    def subject(self) -> str:
        return self.tbs_cert['subject']["common_name"]
    
    
    def spki_algorithm(self) -> signatureAlgorithmConfig:
        '''
        return {algorithm: str, parameters: str}
        '''
        signature = self.tbs_cert["signature"]
        config = signatureAlgorithmConfig()
        if signature['algorithm'] == "sha256_rsa":
            config.oid = "1.2.840.113549.1.1.11"
            config.parameters = None
        else:
            exit("Find a new signature algorithm: ")
        
        return config
    
    def certificate_policy(self) -> certpoliciesConfig:
        '''
        "extn_value": [ { "policy_identifier": "id-cp-ipAddr-asNumber", "policy_qualifiers": [ { "policy_qualifier_id": "certification_practice_statement", "qualifier": "https://rpki.afrinic.net/policy/CPS.pdf" } ] } ]
        '''
        config = certpoliciesConfig()
        extensions = self.tbs_cert['extensions']
        has_certificate_policies = False
        certificate_policies_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "certificate_policies":
                has_certificate_policies = True
                certificate_policies_idx = extensions.index(extension)
                break
        if has_certificate_policies is False:
            return None
        config.critical = extensions[certificate_policies_idx]['critical']
        config.policy_identifiers = []
        for i in extensions[certificate_policies_idx]['extn_value']:
            if i['policy_identifier'] == "id-cp-ipAddr-asNumber":
                config.policy_identifiers.append('1.3.6.1.5.5.7.14.2')
            else:
                exit("Find a new policy_identifier: ")
        return config
    
    def basic_constraints(self) -> basicConstraintsConfig:
        '''
        "extn_value": { "ca": true, "path_len": null }
        '''
        extensions = self.tbs_cert['extensions']
        has_basic_constraints = False
        basic_constraints_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "basic_constraints":
                has_basic_constraints = True
                basic_constraints_idx = extensions.index(extension)
                break
        if has_basic_constraints is False:
            return None
        
        config = basicConstraintsConfig()
        config.critical = extensions[basic_constraints_idx]['critical']
        config.ca = extensions[basic_constraints_idx]['extn_value']['ca']
        config.path_length = extensions[basic_constraints_idx]['extn_value']['path_len_constraint']
        if config.path_length is not None:
            exit("Find a new path_len: ")
        return config
    
    def key_usage(self) -> keyUsageConfig:
        '''
        "extn_value": [ "digital_signature", "key_encipherment", ...]
        '''
        extensions = self.tbs_cert['extensions']
        has_key_usage = False
        key_usage_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "key_usage":
                has_key_usage = True
                key_usage_idx = extensions.index(extension)
                break
        if has_key_usage is False:
            return None

        key_usage_t = keyUsage()
        key_usage_t.list_init(extensions[key_usage_idx]['extn_value'])
        config = keyUsageConfig(extensions[key_usage_idx]['critical'], key_usage_t)
        return config
    
    def key_identifier(self) -> bool:
        '''
        critical: bool
        '''
        extensions = self.tbs_cert['extensions']
        has_key_identifier = False
        key_identifier_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "key_identifier":
                has_key_identifier = True
                key_identifier_idx = extensions.index(extension)
                break
        if has_key_identifier is False:
            return None
        
        critical = extensions[key_identifier_idx]['critical']
        return critical
    
    def subject_information_access(self) -> siaConfig:
        '''
        "extn_value": [ { "access_method": "id-ad-caRepository", "access_location": "rsync://rpki.afrinic.net/repository/AfriNIC/" } ]
        '''
        extensions = self.tbs_cert['extensions']
        has_subject_information_access = False
        subject_information_access_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "subject_information_access":
                has_subject_information_access = True
                subject_information_access_idx = extensions.index(extension)
                break
        if has_subject_information_access is False:
            return None

        critical = extensions[subject_information_access_idx]['critical']
        extn_value = extensions[subject_information_access_idx]['extn_value']
        config = siaConfig(critical=critical, accessed=extn_value)
        return config

    def authority_information_access(self) -> aiaConfig:
        extensions = self.tbs_cert['extensions']
        has_authority_information_access = False
        authority_information_access_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "authority_information_access":
                has_authority_information_access = True
                authority_information_access_idx = extensions.index(extension)
                break
        if has_authority_information_access is False:
            return None
        
        critical = extensions[authority_information_access_idx]['critical']
        extn_value = extensions[authority_information_access_idx]['extn_value']
        config = aiaConfig(critical=critical, ca_issuer_uri=extn_value[0]["access_location"])
        return config
      
    def ipaddr_blocks(self) -> ipaddrsConfig:
        '''
        "extn_value": [ { "addressFamily": "IPv4", "ipAddressChoice": [ { "min": "
        '''
        extensions = self.tbs_cert['extensions']
        has_ipaddr_blocks = False
        ipaddr_blocks_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "id-pe-ipAddrBlocks":
                has_ipaddr_blocks = True
                ipaddr_blocks_idx = extensions.index(extension)
                break
        if has_ipaddr_blocks is False:
            return None
        
        critical = extensions[ipaddr_blocks_idx]['critical']
        ipaddr_blocks = extensions[ipaddr_blocks_idx]['extn_value']
        ipv4_addrs = None
        ipv6_addrs = None
        if len(ipaddr_blocks) > 2:
            raise Exception("Too many ipaddr_blocks")
        for block in ipaddr_blocks:
            if block['addressFamily'] == "IPv4":
                ipv4_addrs = []
                for i in block['ipAddressChoice']:
                    if isinstance(i, dict):
                        ipv4_addrs.append(ipv4AddrRange(i['min'], i['max']))
                    elif isinstance(i, str):
                        ipv4_addrs.append(ipv4addr(i))
                    else:
                        exit("Unknown type: ")
            elif block['addressFamily'] == "IPv6":
                ipv6_addrs = []
                for i in block['ipAddressChoice']:
                    if isinstance(i, dict):
                        ipv6_addrs.append(ipv6AddrRange(i['min'], i['max']))
                    elif isinstance(i, str):
                        ipv6_addrs.append(ipv6addr(i))
                    else:
                        exit("Unknown type: ")
            else:
                exit("Find a new addressFamily: ")
        config = ipaddrsConfig(critical=critical, ipv4_addrs=ipv4_addrs, ipv6_addrs=ipv6_addrs)
        return config
    
    def asnum_blocks(self) -> asidConfig:
        '''
        "extn_value": [ { "addressFamily": "AS", "ipAddressChoice": [ { "min": "
        '''
        extensions = self.tbs_cert['extensions']
        has_asnum_blocks = False
        asnum_blocks_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "id-pe-autonomousSysIds":
                has_asnum_blocks = True
                asnum_blocks_idx = extensions.index(extension)
                break
        if has_asnum_blocks is False:
            return None
        
        critical = extensions[asnum_blocks_idx]['critical']
        asnum_blocks = extensions[asnum_blocks_idx]['extn_value']
        assert len(asnum_blocks) == 2
        if len(asnum_blocks) > 2:
            raise Exception("Too many asnum_blocks")
        asnum = asnum_blocks["asnum"]
        asids = []
        for i in asnum:
            if isinstance(i, int):
                asids.append(asid(i))
            elif isinstance(i, dict):
                asids.append(asidRange(i['min'], i['max']))
            else:
                print("Unknown asnum type: ", i)
        config = asidConfig(critical=critical, asids=asids)
        return config
    
    def aki_critical(self) -> bool:
        extensions = self.tbs_cert['extensions']
        has_aki = False
        aki_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "authority_key_identifier":
                has_aki = True
                aki_idx = extensions.index(extension)
                break
        if has_aki is False:
            return None
        
        critical = extensions[aki_idx]['critical']
        return critical

    def crl_distribution_points(self) -> crlConfig:
        extensions = self.tbs_cert['extensions']
        has_crl = False
        crl_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "crl_distribution_points":
                has_crl = True
                crl_idx = extensions.index(extension)
                break
        if has_crl is False:
            return None
        
        critical = extensions[crl_idx]['critical']
        crl_distribution_points = extensions[crl_idx]['extn_value']
        if len(crl_distribution_points) > 1:
            raise Exception("Too many crl_distribution_points")
        if len(crl_distribution_points[0]["distribution_point"]) > 1:
            raise Exception("Too many distribution_point")
        crl_uris = []
        for i in crl_distribution_points:
            crl_uris.append(i['distribution_point'][0])
        config = crlConfig(critical=critical,crl_uris=crl_uris)
        return config
    
    def parser_cacert(self) -> CACertConfig:
        version = self.version()
        serial_number = self.serial_number()
        signature_algorithm = self.signature()
        issuer = self.issuer()
        validity = self.validaty()
        subject = self.subject()
        key_identifier_critical = self.key_identifier()
        basic_constraints = self.basic_constraints()
        key_usage = self.key_usage()
        crl_distribution_points = self.crl_distribution_points()
        authority_information_access = self.authority_information_access()
        subject_information_access = self.subject_information_access()
        certificate_policies = self.certificate_policy()
        ip_address = self.ipaddr_blocks()
        as_id = self.asnum_blocks()
        config = CACertConfig(
            version=version, serial_number=serial_number, signature_algorithm=signature_algorithm,
            issuer=issuer, validityconfig=validity, subject=subject,
            basic_constraints=basic_constraints, key_identifier_critical=key_identifier_critical,
            key_usage=key_usage, crl_distribution_points=crl_distribution_points, aki_critical=False,
            authority_information_access=authority_information_access, subject_information_access=subject_information_access,
            certificate_policies=certificate_policies, ip_address=ip_address, as_id=as_id
        )
        return config
    
class eeCertParser:
    def __init__(self, json_file=None, json_data=None, type="ee"):
        self.type = type
        if json_data is None:
            with open(json_file, "r") as f:
                self.data = json.load(f)
            self.tbs_cert = self.data['tbs_certificate']
            self.signature_algorithm = self.data['signature_algorithm']
        else:
            self.data = json_data
            self.tbs_cert = self.data['tbs_certificate']
            self.signature_algorithm = self.data['signature_algorithm']
        
    def version(self) -> str:
        return self.tbs_cert['version']
    
    def serial_number(self) -> int:
        return self.tbs_cert['serial_number']
    
    def signature(self) -> signatureAlgorithmConfig:
        '''
        "signature": { "algorithm": "sha256_rsa", "parameters": null }
        '''
        signature = self.tbs_cert["signature"]
        config = signatureAlgorithmConfig()
        if signature['algorithm'] == "sha256_rsa":
            config.oid = "1.2.840.113549.1.1.11"
            config.parameters = None
        else:
            exit("Find a new signature algorithm: ")
        
        return config
    
    def issuer(self) -> str:
        return self.tbs_cert['issuer']["common_name"]
    
    def validaty(self) -> validityConfig:
        config = validityConfig()
        not_before = self.tbs_cert['validity']['not_before']
        not_after = self.tbs_cert['validity']['not_after']
        config.not_before = not_before
        config.not_after = not_after
        return validityConfig(not_before, not_after)
    
    def subject(self) -> str:
        return self.tbs_cert['subject']["common_name"]
    
    
    def spki_algorithm(self) -> signatureAlgorithmConfig:
        '''
        return {algorithm: str, parameters: str}
        '''
        signature = self.tbs_cert["signature"]
        config = signatureAlgorithmConfig()
        if signature['algorithm'] == "sha256_rsa" or signature['algorithm'] == "rsa":
            config.oid = "1.2.840.113549.1.1.11"
            config.parameters = None
        else:
            raise Exception("Find a new signature algorithm: ")
        
        return config

    def key_identifier(self) -> bool:
        '''
        critical: bool
        '''
        extensions = self.tbs_cert['extensions']
        has_key_identifier = False
        key_identifier_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "key_identifier":
                has_key_identifier = True
                key_identifier_idx = extensions.index(extension)
                break
        if has_key_identifier is False:
            return None
        
        critical = extensions[key_identifier_idx]['critical']
        return critical
    
    def aki_critical(self) -> bool:
        extensions = self.tbs_cert['extensions']
        has_aki = False
        aki_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "authority_key_identifier":
                has_aki = True
                aki_idx = extensions.index(extension)
                break
        if has_aki is False:
            return None
        
        critical = extensions[aki_idx]['critical']
        return critical

    def key_usage(self) -> keyUsageConfig:
        '''
        "extn_value": [ "digital_signature", "key_encipherment", ...]
        '''
        extensions = self.tbs_cert['extensions']
        has_key_usage = False
        key_usage_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "key_usage":
                has_key_usage = True
                key_usage_idx = extensions.index(extension)
                break
        if has_key_usage is False:
            return None

        key_usage_t = keyUsage()
        key_usage_t.list_init(extensions[key_usage_idx]['extn_value'])
        config = keyUsageConfig(extensions[key_usage_idx]['critical'], key_usage_t)
        return config
    
    def crl_distribution_points(self) -> crlConfig:
        extensions = self.tbs_cert['extensions']
        has_crl = False
        crl_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "crl_distribution_points":
                has_crl = True
                crl_idx = extensions.index(extension)
                break
        if has_crl is False:
            return None
        
        critical = extensions[crl_idx]['critical']
        crl_distribution_points = extensions[crl_idx]['extn_value']
        if len(crl_distribution_points) > 1:
            raise Exception("Too many crl_distribution_points")
        if len(crl_distribution_points[0]["distribution_point"]) > 1:
            raise Exception("Too many distribution_point")
        crl_uris = []
        for i in crl_distribution_points:
            crl_uris.append(i['distribution_point'][0])
        config = crlConfig(critical=critical,crl_uris=crl_uris)
        return config

    def authority_information_access(self) -> aiaConfig:
        extensions = self.tbs_cert['extensions']
        has_authority_information_access = False
        authority_information_access_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "authority_information_access":
                has_authority_information_access = True
                authority_information_access_idx = extensions.index(extension)
                break
        if has_authority_information_access is False:
            return None
        
        critical = extensions[authority_information_access_idx]['critical']
        extn_value = extensions[authority_information_access_idx]['extn_value']
        config = aiaConfig(critical=critical, ca_issuer_uri=extn_value[0]["access_location"])
        return config
    
    def certificate_policy(self) -> certpoliciesConfig:
        '''
        "extn_value": [ { "policy_identifier": "id-cp-ipAddr-asNumber", "policy_qualifiers": [ { "policy_qualifier_id": "certification_practice_statement", "qualifier": "https://rpki.afrinic.net/policy/CPS.pdf" } ] } ]
        '''
        config = certpoliciesConfig()
        extensions = self.tbs_cert['extensions']
        has_certificate_policies = False
        certificate_policies_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "certificate_policies":
                has_certificate_policies = True
                certificate_policies_idx = extensions.index(extension)
                break
        if has_certificate_policies is False:
            return None
        config.critical = extensions[certificate_policies_idx]['critical']
        config.policy_identifiers = []
        for i in extensions[certificate_policies_idx]['extn_value']:
            if i['policy_identifier'] == "id-cp-ipAddr-asNumber":
                config.policy_identifiers.append('1.3.6.1.5.5.7.14.2')
            else:
                raise Exception("Find a new policy_identifier: ")
        return config

    def subject_information_access(self) -> siaConfig:
        '''
        "extn_value": [ { "access_method": "id-ad-caRepository", "access_location": "rsync://rpki.afrinic.net/repository/AfriNIC/" } ]
        '''
        extensions = self.tbs_cert['extensions']
        has_subject_information_access = False
        subject_information_access_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "subject_information_access":
                has_subject_information_access = True
                subject_information_access_idx = extensions.index(extension)
                break
        if has_subject_information_access is False:
            return None

        critical = extensions[subject_information_access_idx]['critical']
        extn_value = extensions[subject_information_access_idx]['extn_value']
        config = siaConfig(critical=critical, accessed=extn_value)
        return config
        
    def ipaddr_blocks(self) -> ipaddrsConfig:
        '''
        "extn_value": [ { "addressFamily": "IPv4", "ipAddressChoice": [ { "min": "
        '''
        extensions = self.tbs_cert['extensions']
        has_ipaddr_blocks = False
        ipaddr_blocks_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "id-pe-ipAddrBlocks":
                has_ipaddr_blocks = True
                ipaddr_blocks_idx = extensions.index(extension)
                break
        if has_ipaddr_blocks is False:
            return None
        
        critical = extensions[ipaddr_blocks_idx]['critical']
        ipaddr_blocks = extensions[ipaddr_blocks_idx]['extn_value']
        ipv4_addrs = None
        ipv6_addrs = None
        if len(ipaddr_blocks) > 2:
            raise Exception("Too many ipaddr_blocks")
        for block in ipaddr_blocks:
            if block['addressFamily'] == "IPv4":
                if block['ipAddressChoice'] is None:
                    continue
                ipv4_addrs = []
                for i in block['ipAddressChoice']:
                    if isinstance(i, dict):
                        ipv4_addrs.append(ipv4AddrRange(i['min'], i['max']))
                    elif isinstance(i, str):
                        ipv4_addrs.append(ipv4addr(i))
                    else:
                        raise Exception("Unknown type: ")
            elif block['addressFamily'] == "IPv6":
                if block['ipAddressChoice'] is None:
                    continue
                ipv6_addrs = []
                for i in block['ipAddressChoice']:
                    if isinstance(i, dict):
                        ipv6_addrs.append(ipv6AddrRange(i['min'], i['max']))
                    elif isinstance(i, str):
                        ipv6_addrs.append(ipv6addr(i))
                    else:
                        raise Exception("Unknown type: ")
            else:
                raise Exception("Find a new addressFamily")
        config = ipaddrsConfig(critical=critical, ipv4_addrs=ipv4_addrs, ipv6_addrs=ipv6_addrs)
        return config
    
    def asnum_blocks(self) -> bool:
        '''
        "extn_value": [ { "addressFamily": "AS", "ipAddressChoice": [ { "min": "
        '''
        extensions = self.tbs_cert['extensions']
        has_asnum_blocks = False
        asnum_blocks_idx = -1
        for extension in extensions:
            if extension['extn_id'] == "id-pe-autonomousSysIds":
                has_asnum_blocks = True
                asnum_blocks_idx = extensions.index(extension)
                break
        if has_asnum_blocks is False:
            return None
        
        critical = extensions[asnum_blocks_idx]['critical']
        return critical
    
    def parse_eecert(self):
        version = self.version()
        serial_number = self.serial_number()
        signature = self.signature()
        issuer = self.issuer()
        validaty = self.validaty()
        subject = self.subject()
        spki_algorithm = self.spki_algorithm()
        key_identifier = self.key_identifier()
        aki_critical = self.aki_critical()
        key_usage = self.key_usage()
        crl_distribution_points = self.crl_distribution_points()
        authority_information_access = self.authority_information_access()
        certificate_policy = self.certificate_policy()
        subject_information_access = self.subject_information_access()
        ipaddr_blocks = self.ipaddr_blocks()
        asnum_blocks = self.asnum_blocks()
        if asnum_blocks is None:
            need_asid = False
            is_mft = False
        else:
            need_asid = True
            is_mft = True
        config = EECertConfig(
                 version=version, serial_number=serial_number, signature_algorithm=signature,
                 issuer=issuer, validityconfig=validaty, subject=subject, need_asid=need_asid,
                 key_identifier_critical=key_identifier,json_file_path=None,key_usage=key_usage, 
                 crl_distribution_points=crl_distribution_points, aki_critical=aki_critical, is_mft=is_mft,
                 authority_information_access=authority_information_access, subject_information_access=subject_information_access,
                 certificate_policies=certificate_policy, ip_address=ipaddr_blocks)
        return config

def parse_cert(file_path):
    cert_parser = certParser(file_path)
    cert_parser.version()
    cert_parser.serial_number()
    (cert_parser.signature())
    (cert_parser.issuer())
    (cert_parser.validaty())
    (cert_parser.subject())
    (cert_parser.spki_algorithm())
    (cert_parser.certificate_policy())
    (cert_parser.basic_constraints())
    (cert_parser.key_usage())
    (cert_parser.key_identifier())
    (cert_parser.subject_information_access())
    (cert_parser.ipaddr_blocks())
    (cert_parser.asnum_blocks())
    
    
if __name__ == "__main__":        

    # cert_parser = certParser(file_path)
    # print(cert_parser.version())
    # print(cert_parser.serial_number())
    # print(cert_parser.signature())
    # print(cert_parser.issuer())
    # print(cert_parser.validaty())
    # print(cert_parser.subject())
    # print(cert_parser.spki_algorithm())
    # print(cert_parser.certificate_policy())
    # print(cert_parser.basic_constraints())
    # print(cert_parser.key_usage())
    # print(cert_parser.key_identifier())
    # print(cert_parser.subject_information_access())
    # print(cert_parser.ipaddr_blocks())
    # print(cert_parser.asnum_blocks())
    import json
    file_path = "./mutation/test/mft_json/ripe-ncc/DEFAULT/27/4a5d71-e11d-4d32-b597-019ec9d9a758/1/aOlYF0Bglex8tceyhrETM0l7lFE.json"
    with open(file_path, "r") as f:
        data = json.load(f)
    data = data["content"]["certificates"][0]
    cert_parser = certParser(json_data=data)
    print(cert_parser.crl_distribution_points())
    




