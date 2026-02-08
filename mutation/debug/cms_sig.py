from asn1crypto import cms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
import os

def load_cms_and_verify(file_path):
    with open(file_path, 'rb') as f:
        cms_data = f.read()

    cms_object = cms.ContentInfo.load(cms_data)
    signed_data = cms_object['content']

    signer_info = signed_data['signer_infos'][0]
    signature = signer_info['signature'].native

    certificates = signed_data['certificates']
    certificate = certificates[0].chosen  

    public_key_info = certificate['tbs_certificate']['subject_public_key_info']
    public_key = load_der_public_key(public_key_info.dump())

    signed_attrs = signer_info['signed_attrs']
    
    signed_attrs_der = signed_attrs.untag().dump(force=True)

    try:
        public_key.verify(
            signature,
            signed_attrs_der,
            padding.PKCS1v15(),
            hashes.SHA256()  
        )
        print("sign valid.")
    except Exception as e:
        print(f"sign failed: {e}")

# cms_path = './my_repo/98978D0208326B1FA28EE77C4C249605FC82D493.mft'
cms_path = "./my_repo/ca_certificate/manifest.mft"
load_cms_and_verify(cms_path)
