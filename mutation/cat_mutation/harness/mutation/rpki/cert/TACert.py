from pyasn1.type import univ, tag, char, constraint
from pyasn1.codec.der.encoder import encode
from pyasn1_modules.rfc5280 import Certificate, TBSCertificate, AlgorithmIdentifier, Name, Time, Validity, SubjectPublicKeyInfo, Extension
from pyasn1_modules.rfc5280 import RelativeDistinguishedName, AttributeTypeAndValue, RDNSequence, Version
from pyasn1_modules import rfc5280, rfc3779
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import struct
from datetime import datetime
from .myip import create_ipv4_address_choice, create_ipv6_address_choice
from .config import CACertConfig, signatureAlgorithmConfig, validityConfig, basicConstraintsConfig, keyUsageConfig, \
    crlConfig, siaConfig, aiaConfig, certpoliciesConfig, ipaddrsConfig, asidConfig, keyUsage, asid, asidRange
from ..mutator.CertMutator import CertMutator
from ..logger.logger import logger
import random

from pyasn1.type import univ, namedtype, tag

class TBSCertificate(univ.Sequence):
    pass

# TBSCertificate.componentType = namedtype.NamedTypes(
#     namedtype.DefaultedNamedType('version',
#                                  Version().subtype(explicitTag=tag.Tag(tag.tagClassContext,
#                                                                        tag.tagFormatSimple, 0)).subtype(value="v1")),
#     namedtype.NamedType('serialNumber', CertificateSerialNumber()),
#     namedtype.NamedType('signature', AlgorithmIdentifier()),
#     namedtype.NamedType('issuer', Name()),
#     namedtype.NamedType('validity', Validity()),
#     namedtype.NamedType('subject', Name()),
#     namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
#     namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier().subtype(
#         implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
#     namedtype.OptionalNamedType('subjectUniqueID', UniqueIdentifier().subtype(
#         implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
#     namedtype.OptionalNamedType('extensions',
#                                 Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
# )
import random
import secrets
import string
from pyasn1.type import char, univ

def generate_mutated_ca_name():
    length = random.randint(4, 12)
    name_chars = [secrets.choice(string.ascii_letters + string.digits) for _ in range(length)]
    if random.random() < 0.1:
        control_char = chr(random.randint(0, 31))
        insert_pos = random.randint(0, length-1)
        name_chars[insert_pos] = control_char
    return ''.join(name_chars)

class CACertificateBuilder:
    def __init__(self,config:CACertConfig=None, rsa_key_path=None, mutator:list[CertMutator]=None, debug=True):
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
        self.tbs_list = []
        if mutator is None:
            self.mutator = []
        else:
            self.mutator = mutator
        if self.config is None:
            self.config = CACertConfig()

    def set_version(self):
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "version":
                mutated = True
                break
        if mutated:
            mutated_version = mutator.mutate_version(self.config.version)
            version = Version(mutated_version)
        else:
            version = Version(self.config.version)
        version_explicit = version.subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        if self.debug:
            print(version_explicit.prettyPrint())
        # self.tbscert.setComponentByName('version', version_explicit)
        self.tbs_list.append(version_explicit)
        # self.tbscert.setComponentByPosition(0, version_explicit)

    def set_serial_number(self):
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "serial_number":
                mutated = True
                break
        if mutated:
            mutated_serial_number = mutator.mutate_serialnum([self.config.serial_number])
            self.tbs_list.append(univ.Integer(mutated_serial_number))
        else:
            # self.tbscert.setComponentByName('serialNumber', univ.Integer(self.config.serial_number))
            self.tbs_list.append(univ.Integer(self.config.serial_number))

    def set_signature_algorithm(self):
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "signature_algorithm":
                mutated = True
                break
        if mutated:
            # mutate oid
            mutated_oid = mutator.mutate_signature()
            algorithm_identifier = AlgorithmIdentifier()
            algorithm_identifier['algorithm'] = univ.ObjectIdentifier(mutated_oid)
        else:
            algorithm_identifier = AlgorithmIdentifier()
            algorithm_identifier['algorithm'] = univ.ObjectIdentifier(self.config.signature_algorithm.oid)
        if self.config.signature_algorithm.parameters is None:
            algorithm_identifier['parameters'] = univ.Null('')
        else:
            raise Exception("signature_algorithm parameters is not None")
        # self.tbscert.setComponentByName('signature', algorithm_identifier)
        # self.tbscert.setComponentByPosition(2, algorithm_identifier)s
        self.tbs_list.append(algorithm_identifier)

    def set_validity(self):
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "validity":
                mutated = True
                break
        if mutated:
            # validityconfig = self.config.validity
            mutated_not_before, mutated_not_after = mutator.mutate_validity()
            
            validity = Validity()
            not_before_time = Time()
            not_before_time.setComponentByName('generalTime', mutated_not_before)
            not_after_time = Time()
            not_after_time.setComponentByName('generalTime', mutated_not_after)
        else:
            validityconfig = self.config.validity
            validity = Validity()
            not_before_time = Time()
            not_before_time.setComponentByName('generalTime', validityconfig.not_before)
            not_after_time = Time()  
            
            future_time_str = "20301125055723Z" 
            
            not_after_time.setComponentByName('generalTime', future_time_str)
            # ===================

        validity.setComponentByName('notBefore', not_before_time)
        validity.setComponentByName('notAfter', not_after_time)
        
        # print(f'DEBUG: Not After set to: {future_time_str}')
        # self.tbscert.setComponentByName('validity', validity)
        # self.tbscert.setComponentByPosition(4, validity)
        self.tbs_list.append(validity)

    def set_issuer(self):
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "issuer":
                print("mutate issuer")
                mutated = True
                break
        
        if mutated:
            issuer_val = generate_mutated_ca_name()
            asn1_value = char.UTF8String(issuer_val)
        else:
            issuer_val = self.config.issuer
            asn1_value = char.PrintableString(issuer_val)

        attribute_type_and_value = AttributeTypeAndValue()
        attribute_type_and_value['type'] = rfc5280.id_at_commonName
        attribute_type_and_value['value'] = asn1_value

        relative_distinguished_name = RelativeDistinguishedName()
        relative_distinguished_name[0] = attribute_type_and_value

        rdn_sequence = RDNSequence()
        rdn_sequence.append(relative_distinguished_name)

        issuer = Name()
        issuer.setComponentByName('rdnSequence', rdn_sequence)
        self.tbs_list.append(issuer)

    def set_subject(self):
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "subject":
                print("mutate subject")
                mutated = True
                break

        if mutated:
            subject_val = generate_mutated_ca_name()
            asn1_value = char.UTF8String(subject_val)
        else:
            subject_val = self.config.subject
            asn1_value = char.PrintableString(subject_val)

        attribute_type_and_value = AttributeTypeAndValue()
        attribute_type_and_value['type'] = rfc5280.id_at_commonName
        attribute_type_and_value['value'] = asn1_value

        relative_distinguished_name = RelativeDistinguishedName()
        relative_distinguished_name[0] = attribute_type_and_value

        rdn_sequence = RDNSequence()
        rdn_sequence.append(relative_distinguished_name)

        subject = Name()
        subject.setComponentByName('rdnSequence', rdn_sequence)
        self.tbs_list.append(subject)

    def set_subjectPublicKeyInfo(self):

        public_key = self.private_key.public_key()
        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        public_key_sequence = univ.Sequence()
        public_key_sequence.setComponentByPosition(0, univ.Integer(n))
        public_key_sequence.setComponentByPosition(1, univ.Integer(e))

        der_encoded_public_key = encode(public_key_sequence)
        self.der_encoded_public_key = der_encoded_public_key
        public_key_bit_string = univ.BitString.fromOctetString(der_encoded_public_key, 0)

        mutated = False
        for mutator in self.mutator:
            print(mutator.mutate_type)
            if mutator.mutate_type == "subjectPublicKeyInfo":
                mutated = True
                break
        
        if mutated:
            mutated_n, mutated_e, mutated_oid, mutated_public_key = mutator.mutate_subjectPublicKeyInfo(n,e,'1.2.840.113549.1.1.1',public_key_bit_string)
            subject_algorithm = AlgorithmIdentifier()
            subject_algorithm['algorithm'] = univ.ObjectIdentifier(mutated_oid)
            subject_algorithm['parameters'] = univ.Null('')

            subject_public_key_info = SubjectPublicKeyInfo()
            subject_public_key_info.setComponentByName('algorithm', subject_algorithm)
            subject_public_key_info.setComponentByName('subjectPublicKey', mutated_public_key)
        else:
            subject_algorithm = AlgorithmIdentifier()
            subject_algorithm['algorithm'] = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
            subject_algorithm['parameters'] = univ.Null('')

            subject_public_key_info = SubjectPublicKeyInfo()
            subject_public_key_info.setComponentByName('algorithm', subject_algorithm)
            subject_public_key_info.setComponentByName('subjectPublicKey', public_key_bit_string)

        # self.tbscert.setComponentByName('subjectPublicKeyInfo', subject_public_key_info)
        # self.tbscert.setComponentByPosition(6, subject_public_key_info)
        self.tbs_list.append(subject_public_key_info)
        
    def set_issuer_unique_id(self):
        issuerUniqueID =  rfc5280.UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        # self.tbscert.setComponentByName('issuerUniqueID', issuerUniqueID)
        # self.tbscert.setComponentByPosition(7, issuerUniqueID)
    
    def set_subject_unique_id(self):
        subjectUniqueID =  rfc5280.UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        # self.tbscert.setComponentByName('subjectUniqueID', subjectUniqueID)
        # self.tbscert.setComponentByPosition(8, subjectUniqueID)
        
    def add_extension(self, extn_id, critical, value):
        extension = Extension()
        extension['extnID'] = extn_id
        extension['critical'] = critical
        extension['extnValue'] = value
        self.extensions.append(extension)
        
    def basic_constraints_extension(self):
        config = self.config.basic_constraints
        if config is None:
            print("Basic constraints extension is None")
            return

        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "basic_constraints":
                mutated = True
                break

        if mutated:
            mutated_oid, mutated_critical, mutated_value_list = mutator.mutate_basic_constraints(
                rfc5280.id_ce_basicConstraints,
                config.critical,
                [config.ca]
            )

            basic_constraints = rfc5280.BasicConstraints()

            basic_constraints.setComponentByPosition(0, univ.Boolean(False))

            if len(mutated_value_list) > 1:
                basic_constraints.setComponentByPosition(1, univ.Integer(0))

            for i, value in enumerate(mutated_value_list):
                if isinstance(value, bool):
                    basic_constraints.setComponentByPosition(i, univ.Boolean(value))
                elif isinstance(value, int):
                    basic_constraints.setComponentByPosition(i, univ.Integer(value))

            self.add_extension(
                mutated_oid,
                mutated_critical,
                univ.OctetString(encode(basic_constraints))
            )

        else:
            basic_constraints = rfc5280.BasicConstraints()

            basic_constraints.setComponentByPosition(0, univ.Boolean(config.ca))

            self.add_extension(
                rfc5280.id_ce_basicConstraints,
                config.critical,
                univ.OctetString(encode(basic_constraints))
            )
    def key_identifier_extension(self):
        config = self.config.key_identifier_critical
        if config is None:
            print("Key identifier extension is None")
            return
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "key_identifier":
                mutated = True
                break
        if mutated:
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
            mutated_oid, mutated_critical, mutated_value = mutator.mutate_key_identifier(
                rfc5280.id_ce_subjectKeyIdentifier, config, subject_key_identifier_hex
            )
            if type(mutated_value) == bytes:
                mutated_value = mutated_value.hex().upper()
            key_identifier = rfc5280.SubjectKeyIdentifier(hexValue=mutated_value)
            self.add_extension(mutated_oid, mutated_critical, univ.OctetString(encode(key_identifier)))
            return mutated_value
        else:        
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
    
    def authority_key_identifier_extension(self, issuer_public_key=None):
        config = self.config.aki_critical
        if config is None:
            print("Authority key identifier extension is None")
            return
        if issuer_public_key is None:
            raise Exception("Issuer public key is required for Authority Key Identifier extension")
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "authority_key_identifier":
                mutated = True
                print("Mutate authority key identifier")
                break
        issuer_public_numbers = issuer_public_key.public_numbers()
        issuer_public_key_sequence = univ.Sequence()
        issuer_public_key_sequence.setComponentByPosition(0, univ.Integer(issuer_public_numbers.n))
        issuer_public_key_sequence.setComponentByPosition(1, univ.Integer(issuer_public_numbers.e))
        der_encoded_issuer_public_key = encode(issuer_public_key_sequence)
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(der_encoded_issuer_public_key)
        authority_key_identifier_hex = digest.finalize().hex()
        if mutated:
            mutated_oid, mutated_critical, mutated_values = mutator.mutate_authority_key_identifier(
                rfc5280.id_ce_authorityKeyIdentifier, config, [authority_key_identifier_hex]
            )
            # authority_key_identifier = rfc5280.AuthorityKeyIdentifier()
            authority_key_identifier = univ.Sequence()
            for i, mutated_value in enumerate(mutated_values):
                if type(mutated_value) == bytes:
                    mutated_value = mutated_value.hex().upper()
                # print("mutated_value: ", mutated_value)
                key_identifier = rfc5280.KeyIdentifier(hexValue=mutated_value).subtype(
                                            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
                authority_key_identifier.setComponentByPosition(i, key_identifier)
            self.add_extension(mutated_oid, mutated_critical, univ.OctetString(encode(authority_key_identifier)))
            return mutated_value
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
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "key_usage":
                mutated = True
                break
        if mutated:
            mutated_oid, mutated_critical, mutated_value = mutator.mutate_key_usage(
                rfc5280.id_ce_keyUsage, config.critical, config.keyUsageBits
            )
            # print(mutated_value)
            #mutated_value="1110000101000000001111110"
            # mutated_value = "101111111"
            # logger.debug("key usage extension mutated")
            # logger.debug("oid:"+str(rfc5280.id_ce_keyUsage))
            # logger.debug("mutated_oid:"+str(mutated_oid))
            # logger.debug("critical:"+str(config.critical))
            # logger.debug("mutated_critical:"+str(mutated_critical))
            # logger.debug("keyUsageBits:"+str(config.keyUsageBits))
            # logger.debug("mutated_value:"+str(mutated_value))
            # key_usage = rfc5280.KeyUsage(binValue="1111110100100010110001011000000001001000111001101000010011101011001011011100110101011110110111000111110111100000101111101011010000000001011001100011100101110101010010011101101101000100010010110100001001000100101011101001100001011111101110001001110100100101100011010001100001100011100101010001000110101110101110001001110111000010100001110100001110111001000010110111010010110000110111101110110011011110110110101101101110010100111110000010011110011000000000101100001110011110011010011101100101100011101110100000")
            key_usage = rfc5280.KeyUsage(binValue=mutated_value)
            # print("key_usage: ", key_usage.prettyPrint())
            self.add_extension(mutated_oid, mutated_critical, univ.OctetString(encode(key_usage)))
            return 
        key_usage = rfc5280.KeyUsage(binValue=config.keyUsageBits)
        # key_usage = rfc5280.KeyUsage(binValue="0000011011")
        self.add_extension(rfc5280.id_ce_keyUsage, config.critical, univ.OctetString(encode(key_usage)))
    
    def crl_distribution_points_extension(self):
        #print("mutate_crl0")
        
        config = self.config.crl_distribution_points
        if config is None:
            print("CRL distribution points extension is None")
            return

        mutated = False
        target_mutator = None
        for mutator in self.mutator:
            #print(mutator.mutate_type)
            if mutator.mutate_type == "crl_distribution_points":
                mutated = True
                #print("mutate_crl")
                target_mutator = mutator
                break
                
        if mutated:
            mutated_oid, mutated_critical, mutated_value = target_mutator.mutate_crl_distribution_points(
                rfc5280.id_ce_cRLDistributionPoints, config.critical, config.crl_uris
            )
            if isinstance(mutated_value, bytes):
                self.add_extension(mutated_oid, mutated_critical, mutated_value)
                return

            crl_distribution_points = rfc5280.CRLDistributionPoints()
            
            for crl_uris in mutated_value:
                distribution_point = rfc5280.DistributionPoint()
                
                distribution_point_name = rfc5280.DistributionPointName().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
                fullNames = rfc5280.GeneralNames().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
                
                for crl_uri in crl_uris:
                    try:
                        fullName = rfc5280.GeneralName()

                        uri_component = char.IA5String(crl_uri).subtype(
                            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
                        fullName.setComponentByName("uniformResourceIdentifier", uri_component)
                        fullNames.append(fullName)
                    except Exception as e:
                        print(f"Error constructing GeneralName for URI '{crl_uri}': {e}")
                
                distribution_point_name.setComponentByName('fullName', fullNames)
                distribution_point['distributionPoint'] = distribution_point_name

                if random.random() < 0.1:
                    distribution_point['reasons'] = rfc5280.ReasonFlags().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
                
                if random.random() < 0.1:
                    distribution_point['cRLIssuer'] = rfc5280.GeneralNames().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))

                crl_distribution_points.append(distribution_point)

            self.add_extension(mutated_oid, mutated_critical, encode(crl_distribution_points))
            return 

        else:
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
                
                crl_distribution_points.append(distribution_point)

        self.add_extension(rfc5280.id_ce_cRLDistributionPoints, config.critical, encode(crl_distribution_points))

    def subject_information_access_extension(self):
        config = self.config.subject_information_access
        if config is None:
            print("Subject information access extension is None")
            return
        
        subject_info_access = rfc5280.SubjectInfoAccessSyntax()
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "subject_information_access":
                mutated = True
                break
        if mutated:
            # pass
            values = []
            for key, value in config.sia.items():
                values.append([key, value])
            mutated_oid, mutated_critical, mutated_values = mutator.mutate_subject_information_access(
                rfc5280.id_pe_subjectInfoAccess, config.critical, values
            )
            for i in mutated_values:
                # Create an AccessDescription
                access_description = rfc5280.AccessDescription()
                access_description.setComponentByName('accessMethod', i[0])
                # Create GeneralName with the correct assignment for URI
                general_name = rfc5280.GeneralName()
                # uri_component = char.IA5String(config.ca_issuer_uri).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
                if isinstance(i[1], str):
                    uri_component = char.IA5String(i[1]).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
                    # print("str uri_component: ", uri_component)
                    general_name.setComponentByName("uniformResourceIdentifier", uri_component)  # Position 6 corresponds to uniformResourceIdentifier in GeneralName
                elif isinstance(i[1], bytes):
                    uri_component = univ.OctetString(i[1]).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
                    # print("bytes uri_component: ", uri_component)
                    general_name.setComponentByName("iPAddress", uri_component)  # Position 6 corresponds to uniformResourceIdentifier in GeneralName
                # Set the accessLocation
                access_description.setComponentByName('accessLocation', general_name)
                subject_info_access.append(access_description) 
            self.add_extension(mutated_oid, mutated_critical, univ.OctetString(encode(subject_info_access)))
            
        else:
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
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "authority_information_access":
                mutated = True
                break
        if mutated:
            mutated_oid, mutated_critical, mutated_values = mutator.mutate_authority_information_access(
                    rfc5280.id_pe_authorityInfoAccess, config.critical, [[rfc5280.id_ad_caIssuers, config.ca_issuer_uri]]
            )
            authority_info_access = rfc5280.AuthorityInfoAccessSyntax()
            for i in mutated_values:
                # Create an AccessDescription
                access_description = rfc5280.AccessDescription()
                access_description.setComponentByName('accessMethod', i[0])
                # Create GeneralName with the correct assignment for URI
                general_name = rfc5280.GeneralName()
                # uri_component = char.IA5String(config.ca_issuer_uri).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
                if isinstance(i[1], str):
                    uri_component = char.IA5String(i[1]).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
                    # print("str uri_component: ", uri_component)
                    general_name.setComponentByName("uniformResourceIdentifier", uri_component)  # Position 6 corresponds to uniformResourceIdentifier in GeneralName
                elif isinstance(i[1], bytes):
                    uri_component = univ.OctetString(i[1]).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
                    # print("bytes uri_component: ", uri_component)
                    general_name.setComponentByName("iPAddress", uri_component)  # Position 6 corresponds to uniformResourceIdentifier in GeneralName
                # Set the accessLocation
                access_description.setComponentByName('accessLocation', general_name)
                authority_info_access.append(access_description)  # Append to the SequenceOf
            self.add_extension(mutated_oid, mutated_critical, univ.OctetString(encode(authority_info_access)))
        else:
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
    
    def certificate_policies_extension(self):
        # create CertificatePolicies extension
        #  critical=True, policy_identifier='1.3.6.1.5.5.7.14.2'
        config = self.config.certificate_policies
        if config is None:
            print("Certificate policies extension is None")
            return
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "certificate_policies":
                mutated = True
                break
        if mutated:
            mutated_oid, mutated_critical, mutated_values = mutator.mutate_certificate_policies(
                rfc5280.id_ce_certificatePolicies, config.critical, config.policy_identifiers
            )
            certificate_policies = rfc5280.CertificatePolicies()
            for i in mutated_values:
                policy_info = rfc5280.PolicyInformation()
                policy_info.setComponentByName('policyIdentifier', univ.ObjectIdentifier(i))
                certificate_policies.append(policy_info)
            self.add_extension(mutated_oid, mutated_critical, encode(certificate_policies))
        else:
            certificate_policies = rfc5280.CertificatePolicies()
            for policy_identifier in config.policy_identifiers:
                policy_info = rfc5280.PolicyInformation()
                policy_info.setComponentByName('policyIdentifier', univ.ObjectIdentifier(policy_identifier))
                certificate_policies.append(policy_info)
            self.add_extension(rfc5280.id_ce_certificatePolicies, config.critical, encode(certificate_policies))
        
    def ip_address_extension(self):
        config = self.config.ip_address
        if config is None:
            print("IP address extension is None")
            if self.config.json_file_path is not None:
                print(self.config.json_file_path)
            return
        mutated = False
        for mutator in self.mutator:
            if mutator.mutate_type == "ip_address":
                mutated = True
                break
        if mutated:
            mutated_oid, mutated_critical, mutated_value = mutator.mutate_ip_address(
                rfc3779.id_pe_ipAddrBlocks, config.critical, [config.ipv4_addrs, config.ipv6_addrs]
            )
            ip_addr_blocks = rfc3779.IPAddrBlocks()
            for value in mutated_value:
                address_family = univ.Sequence()
                address_family.setComponentByPosition(0, univ.OctetString(value[0]))
                if value[1] is None:
                    ip_address_choice = rfc3779.IPAddressChoice()
                    ip_address_choice['inherit'] = univ.Null('')
                    address_family.setComponentByPosition(1, ip_address_choice)
                else:
                    ip_address_choice = rfc3779.IPAddressChoice()
                    for i in value[1]:
                        if len(i) == 1:
                            def bytes_to_bitstring(b):
                                return ''.join(f'{byte:08b}' for byte in b)
                            ip_address = rfc3779.IPAddress(bytes_to_bitstring(i[0]))
                            ip_address_or_range = rfc3779.IPAddressOrRange()
                            ip_address_or_range['addressPrefix'] = ip_address
                            ip_address_choice['addressesOrRanges'].append(ip_address_or_range)
                        elif len(i) == 2:
                            def bytes_to_bitstring(b):
                                return ''.join(f'{byte:08b}' for byte in b)
                            ip_address_or_range = rfc3779.IPAddressOrRange()
                            ip_address_or_range['addressRange'] = rfc3779.IPAddressRange()
                            ip_address_or_range['addressRange']['min'] = rfc3779.IPAddress(bytes_to_bitstring(i[0]))
                            ip_address_or_range['addressRange']['max'] = rfc3779.IPAddress(bytes_to_bitstring(i[1]))
                            ip_address_choice['addressesOrRanges'].append(ip_address_or_range)
                        else:
                            assert False, "ip address length is not 1 or 2"
                    address_family.setComponentByPosition(1, ip_address_choice)
                # print(address_family.prettyPrint())
                ip_addr_blocks.append(address_family)
            self.add_extension(mutated_oid, mutated_critical, univ.OctetString(encode(ip_addr_blocks)))
            return
                
        ipv4_address = config.ipv4_addrs
        ipv6_address = config.ipv6_addrs
        # critical=True, ipv4_address=None, ipv6_address=None
        if ipv4_address is None:
            ipv4_family = rfc3779.IPAddressFamily()
            ipv4_family['addressFamily'] = univ.OctetString(struct.pack('!H', 1)).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(2, 3))  # IPv4 AFI
            ip_address_choice = rfc3779.IPAddressChoice()
            ip_address_choice['inherit'] = univ.Null('')
            ipv4_family['ipAddressChoice'] = ip_address_choice
        else:
            ipv4_family = rfc3779.IPAddressFamily()
            ipv4_family['addressFamily'] = univ.OctetString(struct.pack('!H', 1)).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(2, 3))  # IPv4 AFI
            ipv4_family['ipAddressChoice'] = create_ipv4_address_choice(ipv4_address)

        if ipv6_address is None:
            ipv6_family = rfc3779.IPAddressFamily()
            ipv6_family['addressFamily'] = univ.OctetString(struct.pack('!H', 2)).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(2, 3))  # IPv6 AFI
            ip_address_choice = rfc3779.IPAddressChoice()
            ip_address_choice['inherit'] = univ.Null('')
            ipv6_family['ipAddressChoice'] = ip_address_choice
        else:
            ipv6_family = rfc3779.IPAddressFamily()
            ipv6_family['addressFamily'] = univ.OctetString(struct.pack('!H', 2)).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(2, 3))  # IPv6 AFI
            ipv6_family['ipAddressChoice'] = create_ipv6_address_choice(ipv6_address)

        ip_addr_blocks = rfc3779.IPAddrBlocks()
        ip_addr_blocks.append(ipv4_family)
        ip_addr_blocks.append(ipv6_family)
        self.add_extension(rfc3779.id_pe_ipAddrBlocks, config.critical, univ.OctetString(encode(ip_addr_blocks)))
        
    def as_id_extension(self):
        config = self.config.as_id
        if config is None:
            print("AS ID extension is None")
            if self.config.json_file_path is not None:
                print(self.config.json_file_path)
            return
        # if config is None:
        #     as_range = rfc3779.ASRange()
        #     as_id_or_range = rfc3779.ASIdOrRange()
        #     as_id_or_range['range'] = as_range
        #     as_ids_or_ranges_sequence = univ.SequenceOf(componentType=rfc3779.ASIdOrRange())
        #     as_ids_or_ranges_sequence.append(as_id_or_range)
        #     as_ids_or_ranges = rfc3779.ASIdentifierChoice().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        #     as_ids_or_ranges['asIdsOrRanges'] = as_ids_or_ranges_sequence
        #     asnum = as_ids_or_ranges
        #     as_identifiers = rfc3779.ASIdentifiers()
        #     as_identifiers['asnum'] = asnum
        else:
            asnums = config.asids
            as_ids_or_ranges_sequence = univ.SequenceOf(componentType=rfc3779.ASIdOrRange())
            mutated = False
            for mutator in self.mutator:
                if mutator.mutate_type == "as_id":
                    mutated = True
                    break
            if mutated:
                mutated_oid, mutated_critical, mutated_value = mutator.mutate_as_id(
                    rfc3779.id_pe_autonomousSysIds, config.critical, asnums
                )
                for i in mutated_value:
                    as_id_or_range = rfc3779.ASIdOrRange()
                    if len(i) == 1:
                        as_id_or_range['id'] = rfc3779.ASId(i[0])
                    elif len(i) == 2:
                        as_id_or_range = rfc3779.ASIdOrRange()
                        as_range = rfc3779.ASRange()
                        as_range['min'] = rfc3779.ASId(i[0])
                        as_range['max'] = rfc3779.ASId(i[1])
                        as_id_or_range['range'] = as_range
                    else:
                        assert False, "as id length is not 1 or 2"
                    as_ids_or_ranges_sequence.append(as_id_or_range)
                as_ids_or_ranges = rfc3779.ASIdentifierChoice().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
                as_ids_or_ranges['asIdsOrRanges'] = as_ids_or_ranges_sequence
                asnum = as_ids_or_ranges
                as_identifiers = rfc3779.ASIdentifiers()
                as_identifiers['asnum'] = asnum
                self.add_extension(mutated_oid, mutated_critical, univ.OctetString(encode(as_identifiers)))
                        
            else:
                for asnum in asnums:
                    if isinstance(asnum, asid):
                        as_id_or_range = rfc3779.ASIdOrRange()
                        as_id_or_range['id'] = rfc3779.ASId(asnum.asid)
                    elif isinstance(asnum, asidRange):
                        as_id_or_range = rfc3779.ASIdOrRange()
                        as_range = rfc3779.ASRange()
                        as_range['min'] = rfc3779.ASId(asnum.min)
                        as_range['max'] = rfc3779.ASId(asnum.max)
                        as_id_or_range['range'] = as_range
                    else:
                        exit("Unknown asid type")
                    as_ids_or_ranges_sequence.append(as_id_or_range)
                as_ids_or_ranges = rfc3779.ASIdentifierChoice().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
                as_ids_or_ranges['asIdsOrRanges'] = as_ids_or_ranges_sequence
                asnum = as_ids_or_ranges
                as_identifiers = rfc3779.ASIdentifiers()
                as_identifiers['asnum'] = asnum
                self.add_extension(rfc3779.id_pe_autonomousSysIds, config.critical, univ.OctetString(encode(as_identifiers)))

    def build_certificate(self, issuer_private_key=None):
        # self.tbscert.setComponentByName('extensions', self.extensions)
        # self.tbscert.setComponentByPosition(7, self.extensions)
        # self.tbscert.setComponentByPosition(8, self.extensions)
        self.tbs_list.append(self.extensions)
        for i in range(len(self.tbs_list)):
            self.tbscert.setComponentByPosition(i, self.tbs_list[i])

        
        self.cert.setComponentByName('tbsCertificate', self.tbscert)
        algorithm_identifier = AlgorithmIdentifier()
        algorithm_identifier['algorithm'] = univ.ObjectIdentifier('1.2.840.113549.1.1.11')  
        algorithm_identifier['parameters'] = univ.Null('')  
        self.cert.setComponentByName('signatureAlgorithm', algorithm_identifier)
        if self.debug:
            print(self.tbscert.prettyPrint())
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
    pass