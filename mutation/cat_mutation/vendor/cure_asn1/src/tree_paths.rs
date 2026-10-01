use crate::labeling::Label;
use crate::labels::LabelName::*;

pub struct CertificatePaths {
    pub ski: Vec<Label>,
}

impl CertificatePaths {
    pub fn init_nested() -> Self {
        let mut prefix = vec![
            SignedObjectContentInfo.into(),
            SignedObjectContent.into(),
            SignedObjectSignedData.into(),
            SignedObjectCertificateSet.into(),
        ];
        let mut cert_paths = Self::init_cert();
        prefix.extend(cert_paths.ski);
        cert_paths.ski = prefix;
        cert_paths
    }

    pub fn init_cert() -> Self {
        Self {
            ski: vec![
                CertificateSeq.into(),
                Certificate.into(),
                CertFldExtensions.into(),
                CertFldExtensionsSeq.into(),
                CertExtSki.into(),
                CertExtSkiValue.into(),
                CertExtSkiKeyIdentifier.into(),
            ],
        }
    }
}

pub struct SignerInfoPaths {
    pub msg_dgst: Vec<Label>,
    pub signature: Vec<Label>,
}

impl SignerInfoPaths {
    pub fn init() -> Self {
        Self {
            msg_dgst: vec![
                SignedObjectContentInfo.into(),
                SignedObjectContent.into(),
                SignedObjectSignedData.into(),
                SignedObjectSignerInfos.into(),
                SignerInfo.into(),
                SignerInfoSignedAttributes.into(),
                SignerInfoSignedAttributeMessageDigest.into(),
                SignerInfoSignedAttributeMessageDigestValues.into(),
                SignerInfoSignedAttributeMessageDigestAttributeValue.into(),
            ],
            signature: vec![
                SignedObjectContentInfo.into(),
                SignedObjectContent.into(),
                SignedObjectSignedData.into(),
                SignedObjectSignerInfos.into(),
                SignerInfo.into(),
                SignerInfoSignature.into(),
            ],
        }
    }
}

pub struct MFTPaths {
    pub cert_paths: CertificatePaths,
    pub sig_inf_paths: SignerInfoPaths,
}

impl MFTPaths {
    pub fn init() -> Self {
        Self {
            cert_paths: CertificatePaths::init_nested(),
            sig_inf_paths: SignerInfoPaths::init(),
        }
    }
}

pub struct ROAPaths {
    pub cert_paths: CertificatePaths,
    pub sig_inf_paths: SignerInfoPaths,
}

impl ROAPaths {
    pub fn init() -> Self {
        Self {
            cert_paths: CertificatePaths::init_nested(),
            sig_inf_paths: SignerInfoPaths::init(),
        }
    }
}

pub struct CRLPaths {}

impl CRLPaths {
    pub fn init() -> Self {
        Self {}
    }
}
