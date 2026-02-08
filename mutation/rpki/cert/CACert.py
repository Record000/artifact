from pyasn1.type import univ, tag, char, constraint
from pyasn1.codec.der.encoder import encode
from pyasn1_modules.rfc5280 import Certificate, TBSCertificate, AlgorithmIdentifier, Name, Time, Validity, SubjectPublicKeyInfo, Extension
from pyasn1_modules.rfc5280 import RelativeDistinguishedName, AttributeTypeAndValue, RDNSequence, Version
from pyasn1_modules import rfc5280, rfc3779
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import struct
from .config import CACertConfig, signatureAlgorithmConfig, validityConfig, basicConstraintsConfig, keyUsageConfig, \
    crlConfig, siaConfig, aiaConfig, certpoliciesConfig, ipaddrsConfig, asidConfig, keyUsage, asid, asidRange

def create_ipv4_address(prefix):
    address, prefix_len = prefix.split('/')
    prefix_len = int(prefix_len)
    
    address_parts = address.split('.')
    address_bytes = bytes(int(part) for part in address_parts)
    
    total_bits = 32  
    used_bits = prefix_len  
    unused_bits = total_bits - used_bits
    
    address_bin = ''.join(format(byte, '08b') for byte in address_bytes)
    
    address_bin_prefix = address_bin[:prefix_len]
    
    bit_string = univ.BitString(binValue=address_bin_prefix)
    return bit_string

def expand_ipv6_address(address):
    if '::' not in address:
        return ':'.join(f"{int(x, 16):04x}" for x in address.split(':'))

    before_colon, _, after_colon = address.partition('::')

    before_parts = before_colon.split(':') if before_colon else []
    after_parts = after_colon.split(':') if after_colon else []

    zeros_to_add = 8 - len(before_parts) - len(after_parts)

    full_parts = (
        before_parts +
        ['0'] * zeros_to_add +
        after_parts
    )

    expanded_address = ':'.join(f"{int(x, 16):04x}" for x in full_parts)
    return expanded_address

def create_ipv6_address(prefix):
    address, prefix_len = prefix.split('/')
    prefix_len = int(prefix_len)
    
    full_address = expand_ipv6_address(address)
    
    binary_string = ''.join(format(int(part, 16), '016b') for part in full_address.split(':'))
    
    binary_prefix = binary_string[:prefix_len]
    
    bit_string = univ.BitString(binValue=binary_prefix)
    return bit_string

def create_ip_address_or_range(address_prefix, v4=True):
    ip_or_range = rfc3779.IPAddressOrRange()
    if v4:
        ip_or_range['addressPrefix'] = create_ipv4_address(address_prefix)
    else:
        ip_or_range['addressPrefix'] = create_ipv6_address(address_prefix)
    return ip_or_range

def create_ip_address_choice(prefixes, v4=True):
    ip_address_choice = rfc3779.IPAddressChoice()
    ip_address_choice['addressesOrRanges'] = univ.SequenceOf(componentType=rfc3779.IPAddressOrRange())
    for prefix in prefixes:
        ip_address_choice['addressesOrRanges'].append(create_ip_address_or_range(prefix, v4=v4))
    return ip_address_choice


class CACertificateBuilder:
    def __init__(self, config:CACertConfig=None, rsa_key_path=None, debug=True):
        self.tbscert = TBSCertificate()
        self.cert = Certificate()
        self.extensions = rfc5280.Extensions().subtype(
                            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        self.debug = debug
        if rsa_key_path:
            with open(rsa_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        else:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.config = config
        if self.config is None:
            self.config = CACertConfig()

    def set_version(self):
        version = Version(self.config.version)
        version_explicit = version.subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        self.tbscert.setComponentByName('version', version_explicit)

    def set_serial_number(self):
        serial_number = self.config.serial_number
        self.tbscert.setComponentByName('serialNumber', univ.Integer(serial_number))

    def set_signature_algorithm(self):
        oid = self.config.signature_algorithm.oid
        algorithm_identifier = AlgorithmIdentifier()
        algorithm_identifier['algorithm'] = univ.ObjectIdentifier(oid)
        if self.config.signature_algorithm.parameters is None:
            algorithm_identifier['parameters'] = univ.Null()
        else:
            raise Exception("signature_algorithm parameters is not None")
        self.tbscert.setComponentByName('signature', algorithm_identifier)

    def set_issuer(self):
        common_name = self.config.issuer
        attribute_type_and_value = AttributeTypeAndValue()
        attribute_type_and_value['type'] = rfc5280.id_at_commonName
        attribute_type_and_value['value'] = char.PrintableString(common_name)

        relative_distinguished_name = RelativeDistinguishedName()
        relative_distinguished_name[0] = attribute_type_and_value

        rdn_sequence = RDNSequence()
        rdn_sequence.append(relative_distinguished_name)

        issuer = Name()
        issuer.setComponentByName('rdnSequence', rdn_sequence)
        self.tbscert.setComponentByName('issuer', issuer)

    def set_validity(self):
        validityconfig = self.config.validity
        validity = Validity()
        not_before_time = Time()
        not_before_time.setComponentByName('generalTime', validityconfig.not_before)
        not_after_time = Time()
        not_after_time.setComponentByName('generalTime', validityconfig.not_after)
        validity.setComponentByName('notBefore', not_before_time)
        validity.setComponentByName('notAfter', not_after_time)
        self.tbscert.setComponentByName('validity', validity)

    def set_subject(self):
        common_name = self.config.subject
        attribute_type_and_value = AttributeTypeAndValue()
        attribute_type_and_value['type'] = rfc5280.id_at_commonName
        attribute_type_and_value['value'] = char.PrintableString(common_name)

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
        subject_algorithm['parameters'] = univ.Null()

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
        extension = Extension()
        extension['extnID'] = extn_id
        extension['critical'] = critical
        extension['extnValue'] = value
        self.extensions.append(extension)
        
    def basic_constraints_extension(self):
        ca = self.config.basic_constraints.ca
        critical = self.config.basic_constraints.critical

        basic_constraints = rfc5280.BasicConstraints()
        basic_constraints['cA'] = ca
        self.add_extension(rfc5280.id_ce_basicConstraints, critical, univ.OctetString(encode(basic_constraints)))
        
    
    def key_identifier_extension(self):
        critical = self.config.key_identifier_critical
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
        self.add_extension(rfc5280.id_ce_subjectKeyIdentifier, critical, univ.OctetString(encode(key_identifier)))
        return subject_key_identifier_hex
    
    def authority_key_identifier_extension(self, issuer_public_key=None):
        config = self.config.aki_critical
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
        # ('digitalSignature', 0),
        # ('nonRepudiation', 1),
        # ('keyEncipherment', 2),
        # ('dataEncipherment', 3),
        # ('keyAgreement', 4),
        # ('keyCertSign', 5),
        # ('cRLSign', 6),
        # ('encipherOnly', 7),
        # ('decipherOnly', 8)
        config = self.config.key_usage
        if config is None:
            print("Key usage extension is None")
            return
        key_usage = rfc5280.KeyUsage(binValue=config.keyUsageBits)
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
            fullName.setComponentByName("uniformResourceIdentifier", uri_component)  # Position 6 corresponds to uniformResourceIdentifier in GeneralName
            fullNames.append(fullName)
            distribution_point_name.setComponentByName('fullName', fullNames)
            distribution_point['distributionPoint'] = distribution_point_name
            distribution_point['reasons'] = rfc5280.ReasonFlags().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
            distribution_point['cRLIssuer'] = rfc5280.GeneralNames().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
            crl_distribution_points.append(distribution_point)

        self.add_extension(rfc5280.id_ce_cRLDistributionPoints, config.critical, encode(crl_distribution_points))

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
            general_name.setComponentByName("uniformResourceIdentifier", uri_component)  # Position 6 corresponds to uniformResourceIdentifier in GeneralName
            access_description.setComponentByName('accessLocation', general_name)
            subject_info_access.append(access_description)
   
        self.add_extension(rfc5280.id_pe_subjectInfoAccess, config.critical, univ.OctetString(encode(subject_info_access)))
                                                                                    
    
    def authority_information_access_extension(self):
        config = self.config.authority_information_access
        if config is None:
            print("Authority information access extension is None")
            return
        authority_info_access = rfc5280.AuthorityInfoAccessSyntax()
        # Create an AccessDescription
        access_description = rfc5280.AccessDescription()
        access_description.setComponentByName('accessMethod', rfc5280.id_ad_caIssuers)
        # Create GeneralName with the correct assignment for URI
        general_name = rfc5280.GeneralName()
        uri_component = char.IA5String(config.ca_issuer_uri).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
        general_name.setComponentByName("uniformResourceIdentifier", uri_component)  # Position 6 corresponds to uniformResourceIdentifier in GeneralName
        # Set the accessLocation
        access_description.setComponentByName('accessLocation', general_name)
        authority_info_access.append(access_description)  # Append to the SequenceOf
        self.add_extension(rfc5280.id_pe_authorityInfoAccess, config.critical, univ.OctetString(encode(authority_info_access)))
    
    def certificate_policies_extension(self, critical=True, policy_identifier='1.3.6.1.5.5.7.14.2'):
        # create CertificatePolicies extension
        certificate_policies = rfc5280.CertificatePolicies()

        policy_info = rfc5280.PolicyInformation()
        policy_info.setComponentByName('policyIdentifier', univ.ObjectIdentifier(policy_identifier))
        certificate_policies.append(policy_info)
        self.add_extension(rfc5280.id_ce_certificatePolicies, critical, encode(certificate_policies))
        
    def ip_address_extension(self, critical=True, ipv4_address=None, ipv6_address=None):
        if ipv4_address is None:
            ipv4_family = rfc3779.IPAddressFamily()
            ipv4_family['addressFamily'] = univ.OctetString(struct.pack('!H', 1)).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(2, 3))  # IPv4 AFI
            ip_address_choice = rfc3779.IPAddressChoice()
            ip_address_choice['inherit'] = univ.Null()
            ipv4_family['ipAddressChoice'] = ip_address_choice
        else:
            ipv4_family = rfc3779.IPAddressFamily()
            ipv4_family['addressFamily'] = univ.OctetString(struct.pack('!H', 1)).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(2, 3))  # IPv4 AFI
            ipv4_family['ipAddressChoice'] = create_ip_address_choice(ipv4_address)

        if ipv6_address is None:
            ipv6_family = rfc3779.IPAddressFamily()
            ipv6_family['addressFamily'] = univ.OctetString(struct.pack('!H', 2)).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(2, 3))  # IPv6 AFI
            # ipv6_family['ipAddressChoice'] = create_ip_address_choice(['::/8'], v4=False)
            ip_address_choice = rfc3779.IPAddressChoice()
            ip_address_choice['inherit'] = univ.Null()
            ipv6_family['ipAddressChoice'] = ip_address_choice
        else:
            ipv6_family = rfc3779.IPAddressFamily()
            ipv6_family['addressFamily'] = univ.OctetString(struct.pack('!H', 2)).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(2, 3))  # IPv6 AFI
            ipv6_family['ipAddressChoice'] = create_ip_address_choice(['::/8'], v4=False)

        ip_addr_blocks = rfc3779.IPAddrBlocks()
        ip_addr_blocks.append(ipv4_family)
        ip_addr_blocks.append(ipv6_family)
        self.add_extension(rfc3779.id_pe_ipAddrBlocks, critical, univ.OctetString(encode(ip_addr_blocks)))
        
    def as_id_extension(self, critical=True, as_min=None, as_max=None):
        if as_min is None and as_max is None:
            as_range = rfc3779.ASRange()
            as_id_or_range = rfc3779.ASIdOrRange()
            as_id_or_range['range'] = as_range
            as_ids_or_ranges_sequence = univ.SequenceOf(componentType=rfc3779.ASIdOrRange())
            as_ids_or_ranges_sequence.append(as_id_or_range)
            as_ids_or_ranges = rfc3779.ASIdentifierChoice().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
            as_ids_or_ranges['asIdsOrRanges'] = as_ids_or_ranges_sequence
            asnum = as_ids_or_ranges
            as_identifiers = rfc3779.ASIdentifiers()
            as_identifiers['asnum'] = asnum
        else:
            as_range = rfc3779.ASRange()
            as_range['min'] = rfc3779.ASId(0)
            as_range['max'] = rfc3779.ASId(4294967295)

            as_id_or_range = rfc3779.ASIdOrRange()
            as_id_or_range['range'] = as_range

            as_ids_or_ranges_sequence = univ.SequenceOf(componentType=rfc3779.ASIdOrRange())
            as_ids_or_ranges_sequence.append(as_id_or_range)

            as_ids_or_ranges = rfc3779.ASIdentifierChoice().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
            as_ids_or_ranges['asIdsOrRanges'] = as_ids_or_ranges_sequence
            asnum = as_ids_or_ranges

            as_identifiers = rfc3779.ASIdentifiers()
            as_identifiers['asnum'] = asnum
        self.add_extension(rfc3779.id_pe_autonomousSysIds, critical, univ.OctetString(encode(as_identifiers)))

    def build_certificate(self, issuer_private_key=None):
        self.tbscert.setComponentByName('extensions', self.extensions)
        self.cert.setComponentByName('tbsCertificate', self.tbscert)
        algorithm_identifier = AlgorithmIdentifier()
        algorithm_identifier['algorithm'] = univ.ObjectIdentifier('1.2.840.113549.1.1.11')  
        algorithm_identifier['parameters'] = univ.Null()
        self.cert.setComponentByName('signatureAlgorithm', algorithm_identifier)
        tbscert_encoded = encode(self.tbscert)
        if issuer_private_key is None:
            issuer_private_key = self.private_key
        signature = issuer_private_key.sign(
            tbscert_encoded,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature = univ.BitString.fromOctetString(signature)
        self.cert.setComponentByName('signature', signature)

    def export_private_key(self, path):
        with open(path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
    def export_public_key(self, path):
        with open(path, 'wb') as f:
            f.write(self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def export_certificate(self, path):
        with open(path, 'wb') as f:
            f.write(encode(self.cert))
    
    def get_cert(self):
        return self.cert

if __name__ == '__main__':
    builder = TACertificateBuilder()
    builder.set_version(2)
    builder.set_serial_number(1)
    builder.set_signature_algorithm()
    builder.set_issuer('ca_certificate')
    builder.set_validity('20241125055723Z', '20301125055723Z')
    builder.set_subject('ca_certificate')
    builder.set_subjectPublicKeyInfo()
    # builder.authority_key_identifier_extension(issuer_public_key=issuer_public_key)
    builder.set_issuer_unique_id()
    builder.set_subject_unique_id()
    builder.basic_constraints_extension()
    builder.key_identifier_extension()
    builder.key_usage_extension()
    # builder.crl_distribution_points_extension()
    # builder.authority_information_access_extension()
    builder.subject_information_access_extension()
    builder.certificate_policies_extension()
    builder.ip_address_extension(critical=True, ipv4_address=['0.0.0.0/8'], ipv6_address=['::/8'])
    builder.as_id_extension(critical=True, as_min=0, as_max=4294967295)
    builder.build_certificate()
    builder.export_certificate('./my_repo/ca_certificate.cer')
    builder.export_private_key('./my_repo/key/ta_private_key.pem')
