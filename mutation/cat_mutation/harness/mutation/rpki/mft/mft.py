from pyasn1.type import univ, namedtype, tag, constraint, useful, char
from pyasn1.codec.der.encoder import encode
from pyasn1_modules import rfc5652
from pyasn1_modules.rfc5652 import SignedData, SignerInfo
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ..cert.EECert import EECertificateBuilder
from ..cert.config import EECertConfig

class FileAndHash(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('file', char.IA5String()),
        namedtype.NamedType('hash', univ.BitString())
    )


class Manifest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', univ.Integer(0).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('manifestNumber', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 2**31-1))),
        namedtype.NamedType('thisUpdate', useful.GeneralizedTime()),
        namedtype.NamedType('nextUpdate', useful.GeneralizedTime()),
        namedtype.NamedType('fileHashAlg', univ.ObjectIdentifier()),
        namedtype.NamedType('fileList', univ.SequenceOf(componentType=FileAndHash()).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(0, 2**31-1)))
    )

    def calculate_file_hash(self, file_path, hash_algorithm="sha256"):
        hash_func = hashlib.new(hash_algorithm)
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):  
                hash_func.update(chunk)
        return hash_func.digest()

    def bytes_to_bitstring(self, byte_data):
        bit_string = ''.join(f'{byte:08b}' for byte in byte_data)
        return tuple(int(bit) for bit in bit_string)

    def bits_to_bytes(self, bits):
        if len(bits) % 8 != 0:
            raise ValueError("Number of bits not a multiple of 8")
        out = []
        for i in range(0, len(bits) >> 3):
            v = 0
            for j in range(0, 8):
                v |= bits[i*8+j] << j
            out.append(v)
        return bytes(out)

    def generate_manifest(self, file_names):
        for file_name in file_names:
            file_hash = self.calculate_file_hash(file_name)
            file_and_hash = FileAndHash()
            file_and_hash['file'] = file_name.split('/')[-1]
            file_and_hash['hash'] = univ.BitString(self.bytes_to_bitstring(file_hash))
            self['fileList'].append(file_and_hash)
        return self

class MFTConfig:
    def __init__(self, ee_config=None):
        self.version = 'v3'
        self.digest_algorithm = '2.16.840.1.101.3.4.2.1'
        self.mft_v = 0
        self.mft_manifest_number = 2**31-2
        self.mft_this_update = '20241125050000Z'
        self.mft_next_update = '20301125055723Z'
        self.mft_file_hash_alg = '2.16.840.1.101.3.4.2.1'
        self.file_names = ["./my_repo/ca_certificate/revoked.crl",
                "./my_repo/ca_certificate/sub_ca.cer"]
        self.encap_content_info_content_type = '1.2.840.113549.1.9.16.1.26'
        self.ee_config = ee_config
        if self.ee_config is None:
            self.ee_config = EECertConfig()

class RPKIManifest:
    def __init__(self, issuer_private_key, config):
        self.signed_data = SignedData()
        self.eecert = None
        self.ee_key = None
        self.issuer_private_key = issuer_private_key
        self.config = config
        if self.config is None:
            self.config = MFTConfig()
        self.manifest = None

    def set_version(self):
        self.signed_data['version'] = self.config.version
    
    def set_digest_algorithm(self):
        digest_algorithms = rfc5652.DigestAlgorithmIdentifiers()
        digest_algorithm = rfc5652.DigestAlgorithmIdentifier()
        digest_algorithm['algorithm'] = univ.ObjectIdentifier(self.config.digest_algorithm)
        digest_algorithm['parameters'] = univ.Null()
        digest_algorithms.append(digest_algorithm)
        self.signed_data['digestAlgorithms'] = digest_algorithms
    
    def set_manifest(self):
        manifest = Manifest()
        manifest['version'] = self.config.mft_v
        manifest['manifestNumber'] = self.config.mft_manifest_number
        manifest['thisUpdate'] = useful.GeneralizedTime(self.config.mft_this_update)
        manifest['nextUpdate'] = useful.GeneralizedTime(self.config.mft_next_update)
        manifest['fileHashAlg'] = univ.ObjectIdentifier(self.config.mft_file_hash_alg)  
        manifest.generate_manifest(self.config.file_names)
        self.manifest = manifest
        return self.manifest
    
    def set_encap_content_info(self):
        encap_content_info = rfc5652.EncapsulatedContentInfo()
        encap_content_info['eContentType'] = univ.ObjectIdentifier(self.config.encap_content_info_content_type)
        encoded_manifest = encode(self.set_manifest())
        tagged_octet_string = univ.OctetString(encoded_manifest).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        encap_content_info.setComponentByName('eContent', tagged_octet_string)

        self.signed_data.setComponentByName('encapContentInfo', encap_content_info)
    
    def set_eecert(self, issuer_private_key):
        self.config.ee_config.is_mft = True 
        builder = EECertificateBuilder(issuer_private_key=issuer_private_key,config=self.config.ee_config)
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
        builder.as_id_extension()
        builder.build_certificate()
        self.eecert = builder.get_cert()
        self.ee_key = builder.export_private_key()
        ee_private_key_path = "./my_repo/key/mft_ee_private_key.pem"
        builder.save_private_key(ee_private_key_path)
        builder.export_certificate("./my_repo/ca_certificate/mft_ee.cer")
        # print(f"EE Certificate exported to ./my_repo/ca_certificate/mft_ee.cer")
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
        # digest_algorithm ==> SHA-256   
        signer_info['digestAlgorithm'] = rfc5652.DigestAlgorithmIdentifier()
        signer_info['digestAlgorithm']['algorithm'] = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')  # OID for SHA-256
        signer_info['digestAlgorithm']['parameters'] = univ.Null()
        signer_info_signed_attrs = rfc5652.SignedAttributes().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        # add content-type to signedAttrs
        content_type_attr = rfc5652.Attribute()
        content_type_attr['attrType'] = univ.ObjectIdentifier('1.2.840.113549.1.9.3')  # OID for content-type
        content_type_attr['attrValues'].append(univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.26'))  # Example OID

        # Step 2: calc Manifest 's SHA-256 
        digest = hashes.Hash(hashes.SHA256())
        digest.update(encode(self.manifest))
        computed_digest = digest.finalize()
        
        # add message-digest to signedAttrs
        message_digest_attr = rfc5652.Attribute()
        message_digest_attr['attrType'] = univ.ObjectIdentifier('1.2.840.113549.1.9.4')  # OID for message-digest
        message_digest_attr['attrValues'].append(univ.OctetString(computed_digest))
        
        # # add signing-time to signedAttrs
        signing_time_attr = rfc5652.Attribute()
        signing_time_attr['attrType'] = univ.ObjectIdentifier('1.2.840.113549.1.9.5')
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
    
    def export_cms(self, file_path='./my_repo/ca_certificate/manifest.mft'):

        content_info = rfc5652.ContentInfo()
        content_info.setComponentByName('contentType', rfc5652.ContentType('1.2.840.113549.1.7.2'))
        content_info.setComponentByName('content', self.signed_data)

        encoded_cms = encode(content_info)
        with open(file_path, 'wb') as f:
            f.write(encoded_cms)
        # print(f"Manifest exported to {file_path}")

if __name__ == '__main__':
    issuer_rsa_key_path = "./my_repo/key/ta_private_key.pem"
    with open(issuer_rsa_key_path, 'rb') as f:
        issuer_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    file_names = ["./my_repo/ca_certificate/revoked.crl",
                "./my_repo/ca_certificate/sub_ca.cer"]
    mft = RPKIManifest(issuer_private_key)
    mft.set_version()
    mft.set_digest_algorithm()
    mft.set_encap_content_info()
    subject_key_identifier_hex = mft.set_eecert(issuer_private_key=issuer_private_key)
    mft.set_certificate_set()
    mft.set_crls()
    mft.set_signer_info(subject_key_identifier_hex)
    mft.export_cms(file_path='./my_repo/ca_certificate/manifest.mft')