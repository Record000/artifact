from pyasn1.type import univ, char, tag, namedtype
from pyasn1_modules import rfc5280
from pyasn1.codec.der.encoder import encode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from .config import CRLConfig, RevokeCertConfig, CrlNumConfig

import binascii

class RevokedCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('userCertificate', rfc5280.CertificateSerialNumber()),
        namedtype.NamedType('revocationDate', rfc5280.Time()),
        namedtype.OptionalNamedType('crlEntryExtensions', rfc5280.Extensions())
    )


class CRLBuilder:
    
    def __init__(self, issuer_private_key=None, config=None):
        self.config = config
        if self.config is None:
            self.config = CRLConfig()
        self.issuer_private_key = issuer_private_key
        if self.issuer_private_key is None:
            # exit("Issuer private key is required")
            raise ValueError("Issuer private key is required")
        self.tbs_cert_list = rfc5280.TBSCertList()
        self.crl = rfc5280.CertificateList()
        self.extensions = rfc5280.Extensions().subtype(
                                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        
    def set_version(self):
        self.tbs_cert_list.setComponentByName('version', rfc5280.Version(self.config.version))
        
    def set_signature_algorithm(self):
        signature_algorithm = rfc5280.AlgorithmIdentifier()
        signature_algorithm['algorithm'] = univ.ObjectIdentifier(self.config.signature_algorithm.oid)
        signature_algorithm['parameters'] = univ.Null()
        self.tbs_cert_list.setComponentByName('signature', signature_algorithm)

    def set_issuer(self):
        issuer_name = rfc5280.Name()
        rdn_sequence = rfc5280.RDNSequence()
        rdn_set = rfc5280.RelativeDistinguishedName()
        rdn_value = rfc5280.AttributeTypeAndValue()
        rdn_value.setComponentByName('type', rfc5280.id_at_commonName)
        rdn_value.setComponentByName('value', char.UTF8String(self.config.issuer))
        rdn_set.setComponentByPosition(0, rdn_value)
        rdn_sequence.setComponentByPosition(0, rdn_set)
        issuer_name.setComponentByPosition(0, rdn_sequence)
        self.tbs_cert_list.setComponentByName('issuer', issuer_name)
        
    def set_revoke_certificates(self):
        if self.config.revoked_certificates is None or len(self.config.revoked_certificates) == 0:
            return
        revoked_certificates = self.config.revoked_certificates
        for cert in revoked_certificates:
            revoke_cert = RevokedCertificate()
            userCertificate = rfc5280.CertificateSerialNumber(cert.user_certificate)
            revocationDate = rfc5280.Time().setComponentByName('generalTime', cert.revocation_date)
            revoke_cert["userCertificate"] = userCertificate
            revoke_cert["revocationDate"] = revocationDate
            self.tbs_cert_list["revokedCertificates"].append(revoke_cert)
        
    def set_this_update(self):
        self.tbs_cert_list.setComponentByName('thisUpdate', rfc5280.Time().setComponentByName('generalTime', self.config.this_update))
        
    def set_next_update(self):
        self.tbs_cert_list.setComponentByName('nextUpdate', rfc5280.Time().setComponentByName('generalTime', self.config.next_update))
        
    def add_extension(self, extnID, critical, value):
        ext = rfc5280.Extension()
        ext.setComponentByName('extnID', univ.ObjectIdentifier(extnID))
        ext.setComponentByName('critical', univ.Boolean(critical))
        ext.setComponentByName('extnValue', value)
        self.extensions.append(ext)
        
    def authority_key_identifier_extension(self):
        issuer_public_key = self.issuer_private_key.public_key()
        issuer_public_key_numbers = issuer_public_key.public_numbers()
        issuer_public_key_sequence = univ.Sequence()
        issuer_public_key_sequence.setComponentByPosition(0, univ.Integer(issuer_public_key_numbers.n))
        issuer_public_key_sequence.setComponentByPosition(1, univ.Integer(issuer_public_key_numbers.e))
        der_encoded_issuer_public_key = encode(issuer_public_key_sequence)
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(der_encoded_issuer_public_key)
        authority_key_identifier_hex = digest.finalize().hex()
        key_identifier = rfc5280.KeyIdentifier(hexValue=authority_key_identifier_hex).subtype(
                                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        aki_value = rfc5280.AuthorityKeyIdentifier()
        aki_value.setComponentByName('keyIdentifier', key_identifier)
        self.add_extension(rfc5280.id_ce_authorityKeyIdentifier,critical=self.config.aki_critical, value=univ.OctetString(encode(aki_value)))
        
    def crl_number_extension(self):
        self.add_extension(rfc5280.id_ce_cRLNumber, 
                           critical=self.config.crl_number.critical, 
                           value=encode(univ.Integer(self.config.crl_number.crl_number)))
    
    def build_crl(self):
        self.tbs_cert_list.setComponentByName('crlExtensions', self.extensions)
        self.crl.setComponentByName('tbsCertList', self.tbs_cert_list)
        algorithm_identifier = rfc5280.AlgorithmIdentifier()
        algorithm_identifier['algorithm'] = univ.ObjectIdentifier(self.config.signature_algorithm.oid) 
        algorithm_identifier['parameters'] = univ.Null()  
        self.crl.setComponentByName('signatureAlgorithm', algorithm_identifier)
        # print(self.crl['tbsCertList'])
        tbs_cert_list_der = encode(self.crl['tbsCertList'])
        signature = self.issuer_private_key.sign(tbs_cert_list_der, padding.PKCS1v15(), hashes.SHA256())
        self.crl.setComponentByName('signature', univ.BitString(hexValue=binascii.hexlify(signature).decode()))
        return self.crl
    
    def export_crl(self, filename):
        with open(filename, 'wb') as f:
            f.write(encode(self.crl))
        # print(f"CRL exported to {filename}")

if __name__ == '__main__':
    issuer_private_key_path = "./my_repo/key/ta_private_key.pem"
    issuer_private_key = serialization.load_pem_private_key(open(issuer_private_key_path, 'rb').read(),
                                                            password=None, backend=default_backend())
    builder = CRLBuilder(issuer_private_key=issuer_private_key)
    builder.set_version()
    builder.set_signature_algorithm()
    builder.set_issuer()
    builder.set_this_update()
    builder.set_next_update()
    builder.authority_key_identifier_extension()
    builder.crl_number_extension()
    crl = builder.build_crl()
    builder.export_crl('./my_repo/ca_certificate/revoked.crl')
    