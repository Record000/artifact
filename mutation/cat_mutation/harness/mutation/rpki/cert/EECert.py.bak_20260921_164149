from pyasn1.type import univ, tag, char, constraint
from pyasn1.codec.der.encoder import encode
from pyasn1_modules.rfc5280 import Certificate, TBSCertificate, AlgorithmIdentifier, Name, Time, Validity, SubjectPublicKeyInfo, Extension
from pyasn1_modules.rfc5280 import RelativeDistinguishedName, AttributeTypeAndValue, RDNSequence, Version
from pyasn1_modules import rfc5280, rfc3779
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import struct
from .config import ipv6addr, ipv6AddrRange, ipv4addr, ipv4AddrRange, EECertConfig
from rpki.cert.myip import create_ipv4_address_choice, create_ipv6_address_choice
import random
from datetime import datetime, timedelta
        
class EEMutator:
    def __init__(self):
        self.targets = [
            "version", "serial_number", "validity", 
            "signature_oid", "subject", "key_usage", 
            "ip_resources", "flip_criticality"
        ]

    def generate_mutations(self):
        mutations = {}
        expected_valid = True  
        
        selected_targets = random.sample(self.targets, random.randint(1, 2))
        
        for target in selected_targets:
            is_legal_choice = random.choice([True, False])
            
            if not is_legal_choice:
                expected_valid = False 

            if target == "version":
                if is_legal_choice:
                    mutations['version'] = 2  
                else:
                    mutations['version'] = random.choice([0, 1, -1, 100])
                
            elif target == "serial_number":
                if is_legal_choice:
                    mutations['serial_number'] = random.randint(1, 2**32) 
                else:
                    mutations['serial_number'] = random.choice([-1, 0, 2**160 + 7])
                
            elif target == "validity":
                if is_legal_choice:
                    now = datetime.now()
                    mutations['validity_not_before'] = (now - timedelta(days=1)).strftime("%Y%m%d%H%M%SZ")
                    mutations['validity_not_after'] = (now + timedelta(days=365)).strftime("%Y%m%d%H%M%SZ")
                else:
                    mutations['validity_not_after'] = "20000101000000Z"
                
            elif target == "signature_oid":
                if is_legal_choice:
                    mutations['bad_signature_oid'] = '1.2.840.113549.1.1.11' # sha256WithRSAEncryption
                else:
                    mutations['bad_signature_oid'] = '1.2.840.113549.1.1.4'  # md5WithRSAEncryption
                
            elif target == "subject":
                if is_legal_choice:
                    mutations['subject_empty'] = False
                else:
                    mutations['subject_empty'] = True
                
            elif target == "key_usage":
                if is_legal_choice:
                    mutations['bad_key_usage'] = '1' 
                else:
                    mutations['bad_key_usage'] = '100001' 
                
            elif target == "ip_resources":
                if is_legal_choice:
                    mutations['omit_ip_resources'] = False
                else:
                    mutations['omit_ip_resources'] = True
                
            elif target == "flip_criticality":
                if is_legal_choice:
                    mutations['flip_criticality'] = False
                else:
                    mutations['flip_criticality'] = True

        return mutations, expected_valid


class EECertificateBuilder:
    def __init__(self, issuer_private_key, config: EECertConfig = None, mutations: dict = None):

        self.config = config
        self.mutations = mutations if mutations else {}
        
        if self.config is None:
            raise ValueError("EECertConfig is required")
        self.tbscert = TBSCertificate()
        self.cert = Certificate()
        self.extensions = rfc5280.Extensions().subtype(
                            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        if issuer_private_key is None:
            raise ValueError("Issuer private key is required")
        
        self.issuer_private_key = issuer_private_key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        self.der_encoded_public_key = None

    def set_version(self):
        ver_value = self.config.version
        if 'version' in self.mutations:
            ver_value = self.mutations['version']
            print(f"MUTATION: Force version to {ver_value}")

        version = Version(ver_value)
        version_explicit = version.subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        self.tbscert.setComponentByName('version', version_explicit)

    def set_serial_number(self):
        serial = self.config.serial_number
        if 'serial_number' in self.mutations:
            serial = self.mutations['serial_number']
            print(f"MUTATION: Force serial_number to {serial}")
            
        self.tbscert.setComponentByName('serialNumber', univ.Integer(serial))

    def set_signature_algorithm(self):
        algorithm_identifier = AlgorithmIdentifier()
        oid = self.config.signature_algorithm.oid
        if 'bad_signature_oid' in self.mutations:
            oid = self.mutations['bad_signature_oid']
            print(f"MUTATION: Force internal signature algorithm OID to {oid}")
            
        algorithm_identifier['algorithm'] = univ.ObjectIdentifier(oid)
        if self.config.signature_algorithm.parameters is None:
            algorithm_identifier.setComponentByName('parameters', univ.Null(""))
        else:
            raise Exception("signature_algorithm parameters is not None")
        self.tbscert.setComponentByName('signature', algorithm_identifier)

    def set_issuer(self):
        attribute_type_and_value = AttributeTypeAndValue()
        attribute_type_and_value['type'] = rfc5280.id_at_commonName
        attribute_type_and_value['value'] = char.PrintableString(self.config.issuer)

        relative_distinguished_name = RelativeDistinguishedName()
        relative_distinguished_name[0] = attribute_type_and_value

        rdn_sequence = RDNSequence()
        rdn_sequence.append(relative_distinguished_name)

        issuer = Name()
        issuer.setComponentByName('rdnSequence', rdn_sequence)
        self.tbscert.setComponentByName('issuer', issuer)

    def set_validity(self):
        validity = Validity()
        
        not_before_str = self.config.validity.not_before
        if 'validity_not_before' in self.mutations:
            not_before_str = self.mutations['validity_not_before']
            print(f"MUTATION: Force NotBefore to {not_before_str}")

        not_before_time = Time()
        not_before_time.setComponentByName('generalTime', not_before_str)
        
        not_after_str = self.config.validity.not_after
        
        if 'validity_not_after' in self.mutations:
            not_after_str = self.mutations['validity_not_after']
            print(f"MUTATION: Force NotAfter to {not_after_str}")
        else:
            # not_after_str = "20301125055723Z"
            # print("DEBUG: EECert NotAfter forced to 20301125055723Z (Default Hack)")
            pass 

        not_after_time = Time()
        not_after_time.setComponentByName('generalTime', not_after_str)
        
        validity.setComponentByName('notBefore', not_before_time)
        validity.setComponentByName('notAfter', not_after_time)

        self.tbscert.setComponentByName('validity', validity)

    def set_subject(self):
        if self.mutations.get('subject_empty', False):
            print("MUTATION: Force Subject to be empty Sequence")
            subject = Name()
            subject.setComponentByName('rdnSequence', RDNSequence()) # Empty
            self.tbscert.setComponentByName('subject', subject)
            return

        attribute_type_and_value = AttributeTypeAndValue()
        attribute_type_and_value['type'] = rfc5280.id_at_commonName
        attribute_type_and_value['value'] = char.PrintableString(self.config.subject)

        relative_distinguished_name = RelativeDistinguishedName()
        relative_distinguished_name[0] = attribute_type_and_value

        rdn_sequence = RDNSequence()
        rdn_sequence.append(relative_distinguished_name)

        subject = Name()
        subject.setComponentByName('rdnSequence', rdn_sequence)
        self.tbscert.setComponentByName('subject', subject)

    def set_subjectPublicKeyInfo(self):
        public_key = self.private_key.public_key()
        public_numbers = public_key.public_numbers()

        public_key_sequence = univ.Sequence()
        public_key_sequence.setComponentByPosition(0, univ.Integer(public_numbers.n))
        public_key_sequence.setComponentByPosition(1, univ.Integer(public_numbers.e))

        der_encoded_public_key = encode(public_key_sequence)
        self.der_encoded_public_key = der_encoded_public_key
        public_key_bit_string = univ.BitString.fromOctetString(der_encoded_public_key, 0)

        subject_algorithm = AlgorithmIdentifier()
        subject_algorithm['algorithm'] = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
        subject_algorithm.setComponentByName('parameters', univ.Null(""))

        subject_public_key_info = SubjectPublicKeyInfo()
        subject_public_key_info.setComponentByName('algorithm', subject_algorithm)
        subject_public_key_info.setComponentByName('subjectPublicKey', public_key_bit_string)

        self.tbscert.setComponentByName('subjectPublicKeyInfo', subject_public_key_info)
        
    def set_issuer_unique_id(self):
        issuerUniqueID =  rfc5280.UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        self.tbscert.setComponentByName('issuerUniqueID', issuerUniqueID)
    
    def set_subject_unique_id(self):
        subjectUniqueID =  rfc5280.UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        self.tbscert.setComponentByName('subjectUniqueID', subjectUniqueID)

    def add_extension(self, extn_id, critical, value):

        if self.mutations.get('flip_criticality', False):
            original = critical
            critical = not critical
            print(f"MUTATION: Flipped criticality for {extn_id} from {original} to {critical}")

        extension = Extension()
        extension['extnID'] = extn_id
        extension['critical'] = critical
        extension['extnValue'] = value
        self.extensions.append(extension)
    
    def key_identifier_extension(self):
        config = self.config.key_identifier_critical
        if config is None:
            print("Key identifier extension is None")
            return
        if self.der_encoded_public_key is None:
            public_key = self.private_key.public_key()
            public_numbers = public_key.public_numbers()
            public_key_sequence = univ.Sequence()
            public_key_sequence.setComponentByPosition(0, univ.Integer(public_numbers.n))
            public_key_sequence.setComponentByPosition(1, univ.Integer(public_numbers.e))
            der_encoded_public_key = encode(public_key_sequence)
        else:
            der_encoded_public_key = self.der_encoded_public_key
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(der_encoded_public_key)
        subject_key_identifier = digest.finalize()
        subject_key_identifier_hex = subject_key_identifier.hex()
        key_identifier = rfc5280.SubjectKeyIdentifier(hexValue=subject_key_identifier_hex)
        self.add_extension(rfc5280.id_ce_subjectKeyIdentifier, config, univ.OctetString(encode(key_identifier)))
        return subject_key_identifier_hex
    
    def authority_key_identifier_extension(self):
        config = self.config.aki_critical
        issuer_public_key = self.issuer_private_key.public_key()
        if config is None:
            print("Authority key identifier extension is None")
            return
        if issuer_public_key is None:
            raise Exception("Issuer public key is required for Authority Key Identifier extension")
        issuer_public_numbers = issuer_public_key.public_numbers()
        issuer_public_key_sequence = univ.Sequence()
        issuer_public_key_sequence.setComponentByPosition(0, univ.Integer(issuer_public_numbers.n))
        issuer_public_key_sequence.setComponentByPosition(1, univ.Integer(issuer_public_numbers.e))
        der_encoded_issuer_public_key = encode(issuer_public_key_sequence)
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(der_encoded_issuer_public_key)
        authority_key_identifier_hex = digest.finalize().hex()
        key_identifier = rfc5280.KeyIdentifier(hexValue=authority_key_identifier_hex).subtype(
                                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        
        authority_key_identifier = rfc5280.AuthorityKeyIdentifier()
        authority_key_identifier['keyIdentifier'] = key_identifier
        authority_key_identifier['authorityCertIssuer'] = rfc5280.GeneralNames().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        authority_key_identifier['authorityCertSerialNumber'] = rfc5280.CertificateSerialNumber().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        self.add_extension(rfc5280.id_ce_authorityKeyIdentifier, config, univ.OctetString(encode(authority_key_identifier)))
    
    def key_usage_extension(self):
        config = self.config.key_usage
        if config is None:
            print("Key usage extension is None")
            return
        
        bits = config.keyUsageBits
        if 'bad_key_usage' in self.mutations:
             bits = self.mutations['bad_key_usage'] 
             print(f"MUTATION: Force KeyUsage bits to {bits}")

        key_usage = rfc5280.KeyUsage(binValue=bits)
        self.add_extension(rfc5280.id_ce_keyUsage, config.critical, univ.OctetString(encode(key_usage)))

    def crl_distribution_points_extension(self):
        config = self.config.crl_distribution_points
        if config is None:
            print("CRL distribution points extension is None")
            return
        
        crl_distribution_points = rfc5280.CRLDistributionPoints()
        
        for crl_uri in config.crl_uris:
            distribution_point = rfc5280.DistributionPoint()
            distribution_point_name = rfc5280.DistributionPointName().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
            fullNames = rfc5280.GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
            fullName = rfc5280.GeneralName()
            uri_component = char.IA5String(crl_uri).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
            fullName.setComponentByName("uniformResourceIdentifier", uri_component) 
            fullNames.append(fullName)
            distribution_point_name.setComponentByName('fullName', fullNames)
            distribution_point['distributionPoint'] = distribution_point_name
            distribution_point['reasons'] = rfc5280.ReasonFlags().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
            distribution_point['cRLIssuer'] = rfc5280.GeneralNames().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
            crl_distribution_points.append(distribution_point)

        self.add_extension(rfc5280.id_ce_cRLDistributionPoints, config.critical, encode(crl_distribution_points))
    
    def authority_information_access_extension(self):
        config = self.config.authority_information_access
        if config is None:
            print("Authority information access extension is None")
            return
        
        authority_info_access = rfc5280.AuthorityInfoAccessSyntax()
        access_description = rfc5280.AccessDescription()
        access_description.setComponentByName('accessMethod', rfc5280.id_ad_caIssuers)
        
        general_name = rfc5280.GeneralName()
        uri_component = char.IA5String(config.ca_issuer_uri).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
        general_name.setComponentByName("uniformResourceIdentifier", uri_component) 
        access_description.setComponentByName('accessLocation', general_name)
        authority_info_access.append(access_description) 
        self.add_extension(rfc5280.id_pe_authorityInfoAccess, config.critical, univ.OctetString(encode(authority_info_access)))
        
    def subject_information_access_extension(self):
        config = self.config.subject_information_access
        if config is None:
            print("Subject information access extension is None")
            return
        
        subject_info_access = rfc5280.SubjectInfoAccessSyntax()
        
        for key, value in config.sia.items():
            access_description = rfc5280.AccessDescription()
            access_description.setComponentByName('accessMethod', univ.ObjectIdentifier(key))
            general_name = rfc5280.GeneralName()
            uri_component = char.IA5String(value).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
            general_name.setComponentByName("uniformResourceIdentifier", uri_component)
            access_description.setComponentByName('accessLocation', general_name)
            subject_info_access.append(access_description)
        self.add_extension(rfc5280.id_pe_subjectInfoAccess, config.critical, univ.OctetString(encode(subject_info_access)))
    
    def certificate_policies_extension(self):
        config = self.config.certificate_policies
        if config is None:
            print("Certificate policies extension is None")
            return
        certificate_policies = rfc5280.CertificatePolicies()
        for policy_identifier in config.policy_identifiers:
            policy_info = rfc5280.PolicyInformation()
            policy_info.setComponentByName('policyIdentifier', univ.ObjectIdentifier(policy_identifier))
            certificate_policies.append(policy_info)
        self.add_extension(rfc5280.id_ce_certificatePolicies, config.critical, encode(certificate_policies))
        
    def ip_address_extension(self):
        # ========= MFT EE：must inherit =========
        if self.config.is_mft:
            ip_addr_blocks = rfc3779.IPAddrBlocks()

            # ---------- IPv4 ----------
            ipv4_family = rfc3779.IPAddressFamily()

            ipv4_family.setComponentByName(
                'addressFamily',
                ipv4_family.getComponentByName('addressFamily').clone(
                    struct.pack('!H', 1)  # IPv4 = 1
                )
            )

            ipv4_choice = rfc3779.IPAddressChoice()
            ipv4_choice.setComponentByName('inherit', univ.Null(''))

            ipv4_family.setComponentByName('ipAddressChoice', ipv4_choice)
            ip_addr_blocks.append(ipv4_family)

            # ---------- IPv6 ----------
            ipv6_family = rfc3779.IPAddressFamily()

            ipv6_family.setComponentByName(
                'addressFamily',
                ipv6_family.getComponentByName('addressFamily').clone(
                    struct.pack('!H', 2)  # IPv6 = 2
                )
            )

            ipv6_choice = rfc3779.IPAddressChoice()
            ipv6_choice.setComponentByName('inherit', univ.Null(''))

            ipv6_family.setComponentByName('ipAddressChoice', ipv6_choice)
            ip_addr_blocks.append(ipv6_family)

            self.add_extension(
                rfc3779.id_pe_ipAddrBlocks,
                True,
                univ.OctetString(encode(ip_addr_blocks))
            )
            return

        # ========= ROA / GBR EE：no inherit =========
        if self.mutations.get('omit_ip_resources', False):
            print("MUTATION: Omitting IP Resources Extension")
            return

        config = self.config.ip_address
        if config is None:
            raise ValueError("ROA EE MUST have IP resources")

        if config.ipv4_addrs is None and config.ipv6_addrs is None:
            raise ValueError("ROA EE MUST NOT use inherit")

        ip_addr_blocks = rfc3779.IPAddrBlocks()

        # ---------- IPv4 ----------
        if config.ipv4_addrs is not None:
            ipv4_family = rfc3779.IPAddressFamily()

            ipv4_family.setComponentByName(
                'addressFamily',
                ipv4_family.getComponentByName('addressFamily').clone(
                    struct.pack('!H', 1)
                )
            )

            ipv4_family.setComponentByName(
                'ipAddressChoice',
                create_ipv4_address_choice(config.ipv4_addrs)
            )

            ip_addr_blocks.append(ipv4_family)

        # ---------- IPv6 ----------
        if config.ipv6_addrs is not None:
            ipv6_family = rfc3779.IPAddressFamily()

            ipv6_family.setComponentByName(
                'addressFamily',
                ipv6_family.getComponentByName('addressFamily').clone(
                    struct.pack('!H', 2)
                )
            )

            ipv6_family.setComponentByName(
                'ipAddressChoice',
                create_ipv6_address_choice(config.ipv6_addrs)
            )

            ip_addr_blocks.append(ipv6_family)

        self.add_extension(
            rfc3779.id_pe_ipAddrBlocks,
            True,
            univ.OctetString(encode(ip_addr_blocks))
        )

    def build(self):
        self.set_version()
        self.set_serial_number()
        self.set_signature_algorithm()
        self.set_issuer()
        self.set_validity()
        self.set_subject()
        self.set_subjectPublicKeyInfo()
        # self.set_issuer_unique_id() # Optional
        # self.set_subject_unique_id() # Optional
        
        # Extensions
        self.key_identifier_extension()
        self.authority_key_identifier_extension()
        self.key_usage_extension()
        self.certificate_policies_extension()
        self.ip_address_extension()
        self.authority_information_access_extension()
        self.subject_information_access_extension()
        self.crl_distribution_points_extension()

        self.tbscert.setComponentByName('extensions', self.extensions)
        self.cert.setComponentByName('tbsCertificate', self.tbscert)
        
        # ... signature logic ...
        return self.cert
   
    def as_id_extension(self):
        if not self.config.need_asid:
            return

        # ========= MFT EE：allow inherit =========
        if self.config.is_mft:
            as_ids = rfc3779.ASIdentifiers()

            # ASIdentifierChoice + [0] EXPLICIT
            as_choice = rfc3779.ASIdentifierChoice().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatConstructed,
                                    0)
            )

            as_choice.setComponentByName('inherit', univ.Null(''))
            as_ids.setComponentByName('asnum', as_choice)

            self.add_extension(
                rfc3779.id_pe_autonomousSysIds,
                True,
                univ.OctetString(encode(as_ids))
            )
            return

        # ========= ROA / GBR EE：forbid inherit =========
        roa_asns = self.config.as_ids  # e.g. [65001]

        if not roa_asns:
            raise ValueError("ROA EE MUST have explicit AS identifiers")

        as_ids = rfc3779.ASIdentifiers()

        # ASIdentifierChoice + [0] EXPLICIT
        as_choice = rfc3779.ASIdentifierChoice().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed,
                                0)
        )

        as_ranges = rfc3779.ASIdOrRanges()

        for asn in roa_asns:
            as_id = rfc3779.ASIdOrRange()
            as_id.setComponentByName(
                'id',
                as_id.getComponentByName('id').clone(asn)
            )
            as_ranges.append(as_id)

        as_choice.setComponentByName('asIdsOrRanges', as_ranges)
        as_ids.setComponentByName('asnum', as_choice)

        self.add_extension(
            rfc3779.id_pe_autonomousSysIds,
            True,
            univ.OctetString(encode(as_ids))
        )


    def build_certificate(self):
        self.tbscert.setComponentByName('extensions', self.extensions)
        self.cert.setComponentByName('tbsCertificate', self.tbscert)
        algorithm_identifier = AlgorithmIdentifier()
        algorithm_identifier['algorithm'] = univ.ObjectIdentifier('1.2.840.113549.1.1.11')  #
        algorithm_identifier.setComponentByName('parameters', univ.Null(""))
        self.cert.setComponentByName('signatureAlgorithm', algorithm_identifier)
        tbscert_encoded = encode(self.tbscert)
        signature = self.issuer_private_key.sign(
            tbscert_encoded,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature = univ.BitString.fromOctetString(signature)
        self.cert.setComponentByName('signature', signature)

    def export_private_key(self) -> rsa.RSAPrivateKey:
        return self.private_key

    def save_private_key(self, path):
        with open(path, 'wb') as f:
            f.write(self.issuer_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def export_certificate(self, path):
        with open(path, 'wb') as f:
            f.write(encode(self.cert))
    
    def get_cert(self):
        return self.cert