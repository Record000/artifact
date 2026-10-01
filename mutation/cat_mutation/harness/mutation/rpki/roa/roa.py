from pyasn1.type import univ, namedtype, tag, constraint, useful, char
from pyasn1.codec.der.encoder import encode
from pyasn1_modules import rfc5652
from pyasn1_modules.rfc5652 import SignedData, SignerInfo
from pyasn1_modules import rfc6482
import hashlib
import socket
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ..cert.EECert import EECertificateBuilder, EECertConfig, EEMutator
from ..cert.myip import create_ipv4_address
from .config import ROAConfig
import sys
import time

class Log:
    RESET = "\033[0m"
    RED   = "\033[31m"
    GREEN = "\033[32m"
    BLUE  = "\033[34m"

    @staticmethod
    def _now():
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    @staticmethod
    def _log(color, *args, sep=" ", end="\n", file=sys.stdout):
        msg = sep.join(str(a) for a in args)
        timestamp = Log._now()
        file.write(f"{color}[{timestamp}] {msg}{Log.RESET}{end}")
        file.flush()

    @staticmethod
    def info(*args, **kwargs):
        Log._log(Log.BLUE, *args, **kwargs)

    @staticmethod
    def success(*args, **kwargs):
        Log._log(Log.GREEN, *args, **kwargs)

    @staticmethod
    def error(*args, **kwargs):
        Log._log(Log.RED, *args, file=sys.stderr, **kwargs)
class ROABuilder:
    def __init__(self, issuer_private_key=None, config: ROAConfig=None):
        self.signed_data = SignedData()
        self.eecert = None
        self.ee_key = None
        self.issuer_private_key = issuer_private_key
        self.config = config
        if self.config is None:
            self.config = ROAConfig()
        self.roaauthz = None

    def set_version(self):
        # version is v3
        self.signed_data['version'] = self.config.version
    
    def set_digest_algorithm(self):
        # digest_algorithm : SHA-256
        digest_algorithms = rfc5652.DigestAlgorithmIdentifiers()
        digest_algorithm = rfc5652.DigestAlgorithmIdentifier()
        digest_algorithm['algorithm'] = univ.ObjectIdentifier(self.config.digest_algorithm)
        digest_algorithm['parameters'] = univ.Null()
        digest_algorithms.append(digest_algorithm)
        self.signed_data['digestAlgorithms'] = digest_algorithms
    
    
    def set_roaauthz(self):
        roaauthz = rfc6482.RouteOriginAttestation()
        roaauthz['version'] = 0
        roaauthz['asID'] = 65001
        ipv4_family = rfc6482.ROAIPAddressFamily()
        ipv4_family['addressFamily'] = univ.OctetString(hexValue='0001').subtype(
                subtypeSpec=constraint.ValueSizeConstraint(2, 3))
        for ip in self.config.ee_config.ip_address.ipv4_addrs:
            ipv4_address = rfc6482.ROAIPAddress()
            # '3.21.64.0' => BitString
            ipv4_addr = create_ipv4_address(ip.ipv4_addr)
            ipv4_address['address'] = ipv4_addr
            ipv4_address['maxLength'] = ip.ipv4_addr.split('/')[1]
            ipv4_family['addresses'].append(ipv4_address)

        roaauthz['ipAddrBlocks'].append(ipv4_family)
        self.roaauthz = roaauthz
        
    
    def set_encap_content_info(self):
        # encap_content_info_content_type , routeOriginAuthorization
        encap_content_info = rfc5652.EncapsulatedContentInfo()
        encap_content_info['eContentType'] = univ.ObjectIdentifier(self.config.encap_content_info_content_type)
        encoded_roaauthz = encode(self.roaauthz)
        tagged_octet_string = univ.OctetString(encoded_roaauthz).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        encap_content_info.setComponentByName('eContent', tagged_octet_string)
        self.signed_data.setComponentByName('encapContentInfo', encap_content_info)
    
    def set_eecert(self, issuer_private_key):
        ee_fuzzer = EEMutator()
        current_mutations, expected_valid = ee_fuzzer.generate_mutations()

        Log.error(f"[MUTATE EE VALUE]: {current_mutations}\n[EXPECTED VALIDATION]: {'VALID' if expected_valid else 'INVALID'}")
        builder = EECertificateBuilder(issuer_private_key=issuer_private_key,config=self.config.ee_config, mutations=current_mutations)
        builder.set_version()
        builder.set_serial_number()
        builder.set_signature_algorithm()
        builder.set_issuer()
        builder.set_validity()
        builder.set_subject()
        builder.set_subjectPublicKeyInfo()
        subject_key_identifier_hex = builder.key_identifier_extension()
        # print(f"subject_key_identifier_hex: {subject_key_identifier_hex}")
        builder.authority_key_identifier_extension()
        builder.key_usage_extension()
        builder.crl_distribution_points_extension()
        builder.authority_information_access_extension()
        builder.subject_information_access_extension()
        builder.certificate_policies_extension()
        builder.ip_address_extension()
        #builder.as_id_extension()
        builder.build_certificate()
        self.eecert = builder.get_cert()
        self.ee_key = builder.export_private_key()
        ee_private_key_path = "./my_repo/key/roa_ee_private_key.pem"
        builder.save_private_key(ee_private_key_path)
        
        return subject_key_identifier_hex
    
    def set_certificate_set(self):
        certificate_set = rfc5652.CertificateSet().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        eecert_choice = rfc5652.CertificateChoices()
        eecert_choice.setComponentByName('certificate', self.eecert)
        certificate_set.append(eecert_choice)
        self.signed_data['certificates'] = certificate_set
        
    def set_crls(self):
        self.signed_data.setComponentByName('crls', rfc5652.RevocationInfoChoices().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))  
    
    def set_signer_info(self, subject_key_identifier_hex):
        signer_info = SignerInfo()
        signer_info['version'] = 3

        signer_identifier = rfc5652.SignerIdentifier()
        # print(f"subject_key_identifier_hex in signer_info: {subject_key_identifier_hex}")
        signer_subject_key_identifier = rfc5652.SubjectKeyIdentifier(hexValue=subject_key_identifier_hex).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        signer_identifier.setComponentByName('subjectKeyIdentifier', signer_subject_key_identifier)
        signer_info['sid'] = signer_identifier
        # digest_algorithm : SHA-256   
        signer_info['digestAlgorithm'] = rfc5652.DigestAlgorithmIdentifier()
        signer_info['digestAlgorithm']['algorithm'] = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')  # OID for SHA-256
        signer_info['digestAlgorithm']['parameters'] = univ.Null()
        signer_info_signed_attrs = rfc5652.SignedAttributes().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        # add content-type => signedAttrs
        content_type_attr = rfc5652.Attribute()
        content_type_attr['attrType'] = univ.ObjectIdentifier('1.2.840.113549.1.9.3')  # OID for content-type
        content_type_attr['attrValues'].append(univ.ObjectIdentifier("1.2.840.113549.1.9.16.1.24"))  # Example OID

        digest = hashes.Hash(hashes.SHA256())
        digest.update(encode(self.roaauthz))
        computed_digest = digest.finalize()
        
        # add message-digest => signedAttrs
        message_digest_attr = rfc5652.Attribute()
        message_digest_attr['attrType'] = univ.ObjectIdentifier('1.2.840.113549.1.9.4')  # OID for message-digest
        message_digest_attr['attrValues'].append(univ.OctetString(computed_digest))
        
        # add signing-time => signedAttrs
        signing_time_attr = rfc5652.Attribute()
        signing_time_attr['attrType'] = univ.ObjectIdentifier('1.2.840.113549.1.9.5')
        # 2024-11-25 05:00:00
        time_tmp = '20241125050000Z'
        signing_time_attr['attrValues'].append(useful.GeneralizedTime(time_tmp))

        signer_info_signed_attrs.append(content_type_attr)
        signer_info_signed_attrs.append(message_digest_attr)
        signer_info_signed_attrs.append(signing_time_attr)
        signer_info['signedAttrs'] = signer_info_signed_attrs
        # print(signer_info['signedAttrs'].prettyPrint())

        signer_info_signatureAlgorithm = rfc5652.SignatureAlgorithmIdentifier()
        signer_info_signatureAlgorithm['algorithm'] = univ.ObjectIdentifier('1.2.840.113549.1.1.1')  # rsassa_pkcs1v15
        signer_info_signatureAlgorithm['parameters'] = univ.Null()
        signer_info['signatureAlgorithm'] = signer_info_signatureAlgorithm
        
        signed_attrs = univ.SetOf()
        signed_attrs.setComponentByPosition(0, content_type_attr)
        signed_attrs.setComponentByPosition(1, message_digest_attr)
        signed_attrs.setComponentByPosition(2, signing_time_attr)

        data_to_sign = encode(signed_attrs)
        signature = self.ee_key.sign(
            data_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # class SignatureValue(univ.OctetString):
        signer_info['signature'] = univ.OctetString(signature)
        signer_info['unsignedAttrs'] = rfc5652.UnsignedAttributes().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        signer_infos = rfc5652.SignerInfos()
        signer_infos[0] = signer_info

        self.signed_data.setComponentByName('signerInfos', signer_infos)
    
    def export_cms(self, file_path=None):
        if not file_path:
            exit("Please provide a file path to export the ROA")

        content_info = rfc5652.ContentInfo()
        content_info.setComponentByName('contentType', rfc5652.ContentType('1.2.840.113549.1.7.2'))
        content_info.setComponentByName('content', self.signed_data)

        encoded_cms = encode(content_info)
        with open(file_path, 'wb') as f:
            f.write(encoded_cms)
        # print(f"ROA exported to {file_path}")

if __name__ == '__main__':
    issuer_rsa_key_path = "./my_repo/key/sub_ca_private_key.pem"
    with open(issuer_rsa_key_path, 'rb') as f:
        issuer_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    roa_config = ROAConfig()
    roa_config.ee_config.issuer = "sub_ca"
    roa_config.ee_config.subject = "test_roa"
    roa_config.ee_config.crl_uri = "rsync://localhost:8080/myrpki/ca_certificate/sub_ca/revoked.crl"
    roa_config.ee_config.ca_issuer_uri = "rsync://localhost:8080/myrpki/ca_certificate/sub_ca.cer"
    roa_config.ee_config.sia_uri = "rsync://localhost:8080/myrpki/ca_certificate/sub_ca/test_roa.roa"
    roa_config.ee_config.ipv4_address = ["3.21.64.0/24"]
    
    roa = ROABuilder(issuer_private_key=issuer_private_key, config=roa_config)
    roa.set_version()
    roa.set_digest_algorithm()
    roa.set_roaauthz()
    roa.set_encap_content_info()
    subject_key_identifier_hex = roa.set_eecert(issuer_private_key=issuer_private_key)
    roa.set_certificate_set()
    roa.set_crls()
    roa.set_signer_info(subject_key_identifier_hex)
    roa.export_cms(file_path='./my_repo/ca_certificate/sub_ca/test_roa.roa')

    # file_names = ["./my_repo/ca_certificate/revoked.crl",
    #             "./my_repo/ca_certificate/sub_ca.cer"]
    # mft = RPKIManifest(issuer_private_key)
    # mft.set_version()
    # mft.set_digest_algorithm()
    # mft.set_encap_content_info()
    # subject_key_identifier_hex = mft.set_eecert(issuer_private_key=issuer_private_key)
    # mft.set_certificate_set()
    # mft.set_crls()
    # mft.set_signer_info(subject_key_identifier_hex)
    # mft.export_cms(file_path='./my_repo/ca_certificate/manifest.mft')