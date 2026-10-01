
/// A [`LabelName`] uniquely names a specific token in an ASN.1 tree of an RPKI object (certificate,
/// CMS signed object, etc.).
#[rustfmt::skip]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Hash, PartialOrd, Ord)]
pub enum LabelName {
    /// Signed Object
    SignedObjectContentInfo,
    SignedObjectContentType,
    SignedObjectContent,
    SignedObjectSignedData,

    /// Version
    SignedObjectVersion,

    /// DigestAlgortihmIdentfiers
    SignedObjectDigestAlgorithms,
    SignedObjectDigestAlgorithmIdentifier,
    SignedObjectDigestAlgorithmIdentifierId,
    SignedObjectDigestAlgorithmIdentifierParameters,

    /// Outer eContentInfo
    SignedObjectEncapContentInfo,
    /// eContentType
    EContentType,
    /// eContent
    EContent,
    /// eContent OCTET STRING
    EContentString,
    /// eContent value, like RPKI-ROA
    EContentProfiled,

    /// Route Origin Attestation
    // RoaContent, -> EContentProfiled
    RoaAsid,
    RoaIpAddrBlocks,
    RoaIpAddressFamily,
    RoaIpAddressFamilyAfi,
    RoaIpAddressFamilyAddresses,
    RoaIpAddressSeq(u32),
    RoaIpAddress(u32),
    RoaIpAddressMl(u32),

    /// AS Provider Authorization
    // AspaContent, -> EContentProfiled
    AspaProviderAuthorization,
    AspaVersion,
    AspaVersionValue,
    AspaCustomerAsid,
    AspaProviderAsSeq,

    /// Ghostbuster Record
    // GbrContent,
    GbrVcard,

    /// Manifest
    // MftContent, -> EContentProfiled
    MftVersion,
    MftNumber,
    MftThisUpdate,
    MftNextUpdate,
    MftFileHashAlg,
    MftFileList,
    MftFileAndHash,
    MftFile,
    MftHash,
    /// iManifest
    IMftCrlEntries,
    IMftCrlEntriesSeq,

    SignedObjectCertificateSet,

    // Certificate for Certs / CertificateList for CRLs / CertificateChoices Certificate for SOs
    CertificateSeq,
    /// TBSCertificate for Certs / TBSCertList for CRLs
    Certificate,
    CertificateSignatureAlgorithm,
    CertificateSignatureAlgorithmId,
    CertificateSignatureAlgorithmParameters,
    CertificateSignature,

    /// Certificate Fields
    CertFldVersionSeq,
    CertFldVersion,
    CertFldSerialNumber,
    CertFldSignature,
    CertFldSignatureAlgorithm,
    CertFldSignatureParameters,
    CertFldIssuer,
    /// RelativeDistinguishedName SET
    CertFldIssuerRdnSet,
    CertFldIssuerAttributeTypeAndValue,
    CertFldIssuerAttributeType,
    CertFldIssuerAttributeValue,
    CertFldExtensions,
    CertFldExtensionsSeq,
    CertFldValidity,
    CertFldValidityNotBefore,
    CertFldValidityNotAfter,
    CertFldSubject,
    /// RelativeDistinguishedName SET
    CertFldSubjectRdnSet,
    CertFldSubjectAttributeTypeAndValue,
    CertFldSubjectAttributeType,
    CertFldSubjectAttributeValue,
    CertFldSubjectPublicKeyInfo,
    CertFldSubjectPublicKeyInfoAlgorithm,
    CertFldSubjectPublicKeyInfoAlgorithmId,
    CertFldSubjectPublicKeyInfoAlgorithmParameters,
    CertFldSubjectPublicKeyInfoPublicKey,

    // revokedCertificates
    CrlFldEntries,

    /// Authority Key Identifier [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2
    CertExtAki,
    CertExtAkiOid,
    CertExtAkiValue,
    CertExtAkiSeq,
    CertExtAkiKeyIdentifier,

    /// Subject Key Identifier [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2
    CertExtSki,
    CertExtSkiOid,
    CertExtSkiValue,
    CertExtSkiKeyIdentifier,

    /// Key Usage [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3
    CertExtKu,
    CertExtKuOid,
    CertExtKuCritc,
    CertExtKuValue,
    CertExtKuBitstring,

    /// Certificate Policies [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4
    CertExtCp,
    CertExtCpOid,
    CertExtCpCritc,
    CertExtCpValue,
    CertExtCpSeq,
    CertExtCpPolicyInformation,
    CertExtCpPolicyIdentifierOid,
    CertExtCpPolicyQualifiers,
    CertExtCpPolicyQualifierInfo,
    CertExtCpPolicyQualifierOid, // TODO Certification Practice Statement (CPS) pointer qualifier type
    CertExtCpPolicyQualifier,

    /// Basic Constraints Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9
    CertExtBc,
    CertExtBcOid,
    CertExtBcCritc,
    CertExtBcValue,
    CertExtBcSeq,
    CertExtBcCa,

    /// CRL Distribution Points Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.13
    CertExtCrldp,
    CertExtCrldpOid,
    CertExtCrldpValue,
    CertExtCrldpSeq,
    CertExtCrldpDistributionPoint,
    CertExtCrldpDistributionPointName,
    CertExtCrldpFullName,
    CertExtCrldpUri,

    /// Authority Information Access Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.2.1
    CertExtAia,
    CertExtAiaOid,
    CertExtAiaValue,
    CertExtAiaSeq,
    CertExtAiaAccessDescription,
    CertExtAiaCaIssuersOid,
    CertExtAiaCaIssuersUri,

    /// Subject Information Access Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.2.2
    CertExtSia,
    CertExtSiaOid,
    CertExtSiaValue,
    CertExtSiaSeq,
    CertExtSiaAccessDescription,
    CertExtSiaCaRepositoryOid,
    CertExtSiaCaRepositoryUri,
    CertExtSiaRpkiManifestOid,
    CertExtSiaRpkiManifestUri,
    CertExtSiaNotificationOid,
    CertExtSiaNotificationUri,
    CertExtSiaSignedObjectOid,
    CertExtSiaSignedObjectUri,

    /// IP Address Delegation Extension [RFC3779]
    ///
    /// [RFC3779]: https://www.rfc-editor.org/rfc/rfc3779.html#section-2
    CertExtIp,
    CertExtIpOid,
    CertExtIpCritc,
    CertExtIpValue,
    CertExtIpSeq,
    CertExtIpAddressFamily,
    CertExtIpAddressFamilyId,
    CertExtIpAddressChoice,
    CertExtIpAddressPrefix(u32),
    CertExtIpAddressRange(u32),
    CertExtIpAddressRangeMin(u32),
    CertExtIpAddressRangeMax(u32),

    /// Autonomous System Identifier Delegation Extension [RFC3779]
    ///
    /// [RFC3779]: https://www.rfc-editor.org/rfc/rfc3779.html#section-3
    CertExtAsid,
    CertExtAsidOid,
    CertExtAsidCritc,
    CertExtAsidValue,
    CertExtAsidSeq,
    CertExtAsidAsnum,
    CertExtAsidAsnumIdOrRange,
    CertExtAsidAsnumRageMin,
    CertExtAsidAsnumRageMax,
    CertExtAsidRdi,
    CertExtAsidRdiIdOrRange,
    CertExtAsidRdiRangeMin,
    CertExtAsidRdiRangeMax,

    /// CRL Number Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.3
    CrlExtCrln,
    CrlExtCrlnOid,
    CrlExtCrlnValue,
    /// CRLNumber ::= INTEGER (0..MAX)
    CrlExtCrlnCrlNumber,

    /// signerInfos
    SignedObjectSignerInfos,
    SignerInfo,
    SignerInfoVersion,
    SignerInfoSignerIdentifier,
    SignerInfoDigestAlgorithm,
    SignerInfoDigestAlgorithmIdentifierId,
    SignerInfoDigestAlgorithmIdentifierParameters,
    SignerInfoSignedAttributes,
    SignerInfoSignedAttributeContentType,
    SignerInfoSignedAttributeContentTypeOid,
    SignerInfoSignedAttributeContentTypeValues,
    SignerInfoSignedAttributeContentTypeAttributeValue,
    SignerInfoSignedAttributeMessageDigest,
    SignerInfoSignedAttributeMessageDigestOid,
    SignerInfoSignedAttributeMessageDigestValues,
    SignerInfoSignedAttributeMessageDigestAttributeValue,
    SignerInfoSignedAttributeSigningTime,
    SignerInfoSignedAttributeSigningTimeOid,
    SignerInfoSignedAttributeSigningTimeValues,
    SignerInfoSignedAttributeSigningTimeAttributeValue,
    SignerInfoSignedAttributeBinarySigningTime,
    SignerInfoSignedAttributeBinarySigningTimeOid,
    SignerInfoSignedAttributeBinarySigningTimeValues,
    SignerInfoSignedAttributeBinarySigningTimeAttributeValue,
    SignerInfoSignedAttributeSignature,
    SignerInfoSignedAttributeSignatureOid,
    SignerInfoSignedAttributeSignatureValues,
    SignerInfoSignedAttributeSignatureAttributeValue,
    SignerInfoSignatureAlgorithm,
    SignerInfoSignatureAlgorithmId,
    SignerInfoSignatureAlgorithmParameters,
    SignerInfoSignature,

    Custom(String),
}

impl LabelName {
    #[rustfmt::skip]
    pub fn short_label(&self) -> String {
        use LabelName::*;
        match self {
            // Signed Object
            SignedObjectContentInfo => "contentInfo".into(),
            SignedObjectContentType => "contentType".into(),
            SignedObjectContent => "content".into(),
            SignedObjectSignedData => "signedData".into(),

            SignedObjectVersion => "version".into() ,

            SignedObjectDigestAlgorithms => "digestAlgorithms".into(),
            SignedObjectDigestAlgorithmIdentifier => "digestAlgorithmIdentifier".into(),
            SignedObjectDigestAlgorithmIdentifierId => "digestAlgorithmIdentifierId".into(),
            SignedObjectDigestAlgorithmIdentifierParameters => "digestAlgorithmIdentifierParameters".into(),

            SignedObjectEncapContentInfo => "eContentInfo".into(),
            EContentType => "eContentType".into(),
            EContent => "eContent".into(),
            EContentString => "eContentString".into(),
            EContentProfiled => "eContentProfiled".into(),

            // Route Origin Authorization
            // RoaContent => "roaContent",
            RoaAsid => "roaAsId".into(),
            RoaIpAddrBlocks => "roaIpAddrBlocks".into(),
            RoaIpAddressFamily => "roaIpAddressFamily".into(),
            RoaIpAddressFamilyAfi => "roaIpAddressFamilyAfi".into(),
            RoaIpAddressFamilyAddresses => "roaAddresses".into(),
            RoaIpAddressSeq(ipv) if *ipv == 1 => "roaIpAddressSeq_v4".into(),
            RoaIpAddressSeq(ipv) if *ipv == 2 => "roaIpAddressSeq_v6".into(),
            RoaIpAddressSeq(_ipv) => "roaIpAddressSeq".into(),
            RoaIpAddress(ipv) if *ipv == 1 => "roaIpAddress_v4".into(),
            RoaIpAddress(ipv) if *ipv == 2 => "roaIpAddress_v6".into(),
            RoaIpAddress(_ipv) => "roaIpAddress".into(),
            RoaIpAddressMl(ipv) if *ipv == 1 => "roaIpAddressMl_v4".into(),
            RoaIpAddressMl(ipv) if *ipv == 2 => "roaIpAddressMl_v6".into(),
            RoaIpAddressMl(_ipv) => "roaIpAddressMl".into(),

            // AS Path Attestation
            // AspaContent => "aspaContent",
            AspaProviderAuthorization => "aspaProviderAuthorization".into(),
            AspaVersion => "aspaVersion".into(),
            AspaVersionValue => "aspaVersionValue".into(),
            AspaCustomerAsid => "aspaCustomerAsid".into(),
            AspaProviderAsSeq => "aspaProviderAsSeq".into(),

            // Ghostbuster Record
            // GbrContent => "gbrContent",
            GbrVcard => "gbrVcard".into(),

            // Manifest
            // MftContent => "mftContent",
            MftVersion => "mftVersion".into(),
            MftNumber => "mftNumber".into(),
            MftThisUpdate => "mftThisUpdate".into(),
            MftNextUpdate => "mftNextUpdate".into(),
            MftFileHashAlg => "mftFileHashAlg".into(),
            MftFileList => "mftFileList".into(),
            MftFileAndHash => "mftFileAndHash".into(),
            MftFile => "mftFile".into(),
            MftHash => "mftHash".into(),
            // iManifest
            IMftCrlEntries => "imftCrlEntriesField".into(),
            IMftCrlEntriesSeq => "imftCrlEntries".into(),

            SignedObjectCertificateSet => "certificateSet".into(),

            CertificateSeq => "certificateSeq".into(),
            Certificate => "certificate".into(),
            CertificateSignatureAlgorithm => "certificateSignatureAlgorithm".into(),
            CertificateSignatureAlgorithmId => "certificateSignatureAlgorithmId".into(),
            CertificateSignatureAlgorithmParameters => "certificateSignatureAlgorithmParameters".into(),
            CertificateSignature => "certificateSignature".into(),

            CertFldVersionSeq => "certVersionSeq".into(),
            CertFldVersion => "certVersion".into(),
            CertFldSerialNumber => "certSerialNumber".into(),
            CertFldSignature => "certSignature".into(),
            CertFldSignatureAlgorithm => "certSignatureAlgorithm".into(),
            CertFldSignatureParameters => "certSignatureParameters".into(),
            CertFldIssuer => "certIssuer".into(),
            CertFldIssuerRdnSet => "certIssuerRdnSet".into(),
            CertFldIssuerAttributeTypeAndValue => "certIssuerAttributeTypeAndValue".into(),
            CertFldIssuerAttributeType => "certIssuerAttributeType".into(),
            CertFldIssuerAttributeValue => "certIssuerAttributeValue".into(),
            CertFldExtensions => "certExtensions".into(),
            CertFldExtensionsSeq => "certExtensionsSeq".into(),
            CertFldValidity => "certValidity".into(),
            CertFldValidityNotBefore => "certNotBefore".into(),
            CertFldValidityNotAfter => "certNotAfter".into(),
            CertFldSubject => "certSubject".into(),
            CertFldSubjectRdnSet => "certSubjectRdnSet".into(),
            CertFldSubjectAttributeTypeAndValue => "certSubjectAttributeTypeAndValue".into(),
            CertFldSubjectAttributeType => "certSubjectAttributeType".into(),
            CertFldSubjectAttributeValue => "certSubjectAttributeValue".into(),
            CertFldSubjectPublicKeyInfo => "certSubjectPublicKeyInfo".into(),
            CertFldSubjectPublicKeyInfoAlgorithm => "certSubjectPublicKeyInfoAlgorithm".into(),
            CertFldSubjectPublicKeyInfoAlgorithmId => "certSubjectPublicKeyInfoAlgorithmId".into(),
            CertFldSubjectPublicKeyInfoAlgorithmParameters => "certSubjectPublicKeyInfoAlgorithmParameters".into(),
            CertFldSubjectPublicKeyInfoPublicKey => "certSubjectPublicKeyInfoPublicKey".into(),
            CrlFldEntries => "crlEntries".into(),

            // Authority Key Identifier
            CertExtAki => "authorityKeyIdentifierExt".into(),
            CertExtAkiOid => "authorityKeyIdentifierOid".into(),
            CertExtAkiValue => "authorityKeyIdentifierValue".into(),
            CertExtAkiSeq => "authorityKeyIdentifierSeq".into(),
            CertExtAkiKeyIdentifier => "authorityKeyIdentifierKeyIdentifier".into(),

            // Subject Key Identifier
            CertExtSki => "subjectKeyIdentifierExt".into(),
            CertExtSkiOid => "subjectKeyIdentifierOid".into(),
            CertExtSkiValue => "subjectKeyIdentifierValue".into(),
            CertExtSkiKeyIdentifier => "subjectKeyIdentifierKeyIdentifier".into(),

            // Key Usage
            CertExtKu => "keyUsageExt".into(),
            CertExtKuOid => "keyUsageOid".into(),
            CertExtKuCritc => "keyUsageValue".into(),
            CertExtKuValue => "keyUsageValue".into(),
            CertExtKuBitstring => "keyUsageBitstring".into(),

            // Certificate Policies
            CertExtCp => "certificatePoliciesExt".into(),
            CertExtCpOid => "certificatePoliciesOid".into(),
            CertExtCpCritc => "certificatePoliciesCritc".into(),
            CertExtCpValue => "certificatePoliciesValue".into(),
            CertExtCpSeq => "certificatePoliciesSeq".into(),
            CertExtCpPolicyInformation => "cpPolicyInformation".into(),
            CertExtCpPolicyIdentifierOid => "cpPolicyIdentifierOid".into(),
            CertExtCpPolicyQualifiers => "cpPolicyQualifiers".into(),
            CertExtCpPolicyQualifierInfo => "cpPolicyQualifierInfo".into(),
            CertExtCpPolicyQualifierOid => "cpPolicyQualifierOid".into(),
            CertExtCpPolicyQualifier => "cpPolicyQualifier".into(),

            // Basic Constraints
            CertExtBc => "basicConstraintsExt".into(),
            CertExtBcOid => "basicConstraintsOid".into(),
            CertExtBcCritc => "basicConstraintsCritc".into(),
            CertExtBcValue => "basicConstraintsValue".into(),
            CertExtBcSeq => "basicConstraintsSeq".into(),
            CertExtBcCa => "basicConstraintsCa".into(),

            // CRL Distribution Points
            CertExtCrldp => "crlDistributionPointsExt".into(),
            CertExtCrldpOid => "crlDistributionPointsOid".into(),
            CertExtCrldpValue => "crlDistributionPointsValue".into(),
            CertExtCrldpSeq => "crlDistributionPointsSeq".into(),
            CertExtCrldpDistributionPoint => "crlDistributionPointsDistributionPoint".into(),
            CertExtCrldpDistributionPointName => "crlDistributionPointsDistributionPointName".into(),
            CertExtCrldpFullName => "crlDistributionPointsFullName".into(),
            CertExtCrldpUri => "crlDistributionPointsUri".into(),

            // Authority Information Access
            CertExtAia => "authorityInformationAccessExt".into(),
            CertExtAiaOid => "authorityInformationAccessOid".into(),
            CertExtAiaValue => "authorityInformationAccessValue".into(),
            CertExtAiaSeq => "authorityInformationAccessSeq".into(),
            CertExtAiaAccessDescription => "aiaAccessDescription".into(),
            CertExtAiaCaIssuersOid => "aiaCaIssuersOid".into(),
            CertExtAiaCaIssuersUri => "aiaCaIssuersUri".into(),

            // Subject Information Access
            CertExtSia => "subjectInformationAccessExt".into(),
            CertExtSiaOid => "subjectInformationAccessOid".into(),
            CertExtSiaValue => "subjectInformationAccessValue".into(),
            CertExtSiaSeq => "subjectInformationAccessSeq".into(),
            CertExtSiaAccessDescription => "siaAccessDescription".into(),
            CertExtSiaCaRepositoryOid => "siaCaRepository".into(),
            CertExtSiaCaRepositoryUri => "siaCaRepositoryURI".into(),
            CertExtSiaRpkiManifestOid => "siaRpkiManifest".into(),
            CertExtSiaRpkiManifestUri => "siaRpkiManifestURI".into(),
            CertExtSiaNotificationOid => "siaNotification".into(),
            CertExtSiaNotificationUri => "siaNotificationURI".into(),
            CertExtSiaSignedObjectOid => "siaSignedObject".into(),
            CertExtSiaSignedObjectUri => "siaSignedObjectURI".into(),

            // IP Address Delegation Extension
            CertExtIp => "ipAddressDelegationExt".into(),
            CertExtIpOid => "ipAddressDelegationOid".into(),
            CertExtIpCritc => "ipAddressDelegationCritc".into(),
            CertExtIpValue => "ipAddressDelegationValue".into(),
            CertExtIpSeq => "ipAddressDelegationSeq".into(),
            CertExtIpAddressFamily => "ipAddressDelegationFamily".into(),
            CertExtIpAddressFamilyId => "ipAddressDelegationFamilyId".into(),
            CertExtIpAddressChoice => "ipAddressDelegationIpAddrChoice".into(),
            CertExtIpAddressPrefix(ipv) if *ipv == 1 => "ipAddressDelegation_v4_prefix".into(),
            CertExtIpAddressPrefix(ipv) if *ipv == 2 => "ipAddressDelegation_v6_prefix".into(),
            CertExtIpAddressPrefix(_ipv) => "ipAddressDelegation_prefix".into(),
            CertExtIpAddressRange(ipv) if *ipv == 1 => "ipAddressDelegation_v4_range".into(),
            CertExtIpAddressRange(ipv) if *ipv == 2 => "ipAddressDelegation_v6_range".into(),
            CertExtIpAddressRange(_ipv) => "ipAddressDelegation_range".into(),
            CertExtIpAddressRangeMin(ipv) if *ipv == 1 => "ipAddressDelegation_v4_rangeMin".into(),
            CertExtIpAddressRangeMin(ipv) if *ipv == 2 => "ipAddressDelegation_v6_rangeMin".into(),
            CertExtIpAddressRangeMin(_ipv) => "ipAddressDelegation_rangeMin".into(),
            CertExtIpAddressRangeMax(ipv) if *ipv == 1 => "ipAddressDelegation_v4_rangeMax".into(),
            CertExtIpAddressRangeMax(ipv) if *ipv == 2 => "ipAddressDelegation_v6_rangeMax".into(),
            CertExtIpAddressRangeMax(_ipv) => "ipAddressDelegation_rangeMax".into(),

            // Autonomous System Identifier Delegation Extension
            CertExtAsid => "asIdDelegationExt".into(),
            CertExtAsidOid => "asIdDelegationOid".into(),
            CertExtAsidCritc => "asIdDelegationCritc".into(),
            CertExtAsidValue => "asIdDelegationValue".into(),
            CertExtAsidSeq => "asIdDelegationSeq".into(),
            CertExtAsidAsnum => "asIdDelegationAsnum".into(),
            CertExtAsidAsnumIdOrRange => "asIdDelegationAsnumIdOrRange".into(),
            CertExtAsidAsnumRageMin => "asIdDelegationAsnumRangeMin".into(),
            CertExtAsidAsnumRageMax => "asIdDelegationAsnumRageMax".into(),
            CertExtAsidRdi => "asIdDelegationRdi".into(),
            CertExtAsidRdiIdOrRange => "asIdDelegationRdiOrRange".into(),
            CertExtAsidRdiRangeMin => "asIdDelegationRdiRangeMin".into(),
            CertExtAsidRdiRangeMax => "asIdDelegationRdiRangeMax".into(),

            // CRL Number Extension
            CrlExtCrln => "crlNumberExt".into(),
            CrlExtCrlnOid => "crlNumberOid".into(),
            CrlExtCrlnValue => "crlNumberValue".into(),
            CrlExtCrlnCrlNumber => "crlNumberCrlNumber".into(),

            // signerInfos
            SignedObjectSignerInfos => "signerInfos".into(),
            SignerInfo => "signerInfo".into(),
            SignerInfoVersion => "signerInfoVersion".into(),
            SignerInfoSignerIdentifier => "signerInfoSignerIdentifier".into(),
            SignerInfoDigestAlgorithm => "signerInfoDigestAlgorithm".into(),
            SignerInfoDigestAlgorithmIdentifierId => "signerInfoDigestAlgorithmId".into(),
            SignerInfoDigestAlgorithmIdentifierParameters => "signerInfoDigestAlgorithmParameters".into(),
            SignerInfoSignedAttributes => "signedAttributes".into(),
            SignerInfoSignedAttributeContentType => "signedAttrContentType".into(),
            SignerInfoSignedAttributeContentTypeOid => "signedAttrContentTypeOid".into(),
            SignerInfoSignedAttributeContentTypeValues => "signedAttrContentTypeValues".into(),
            SignerInfoSignedAttributeContentTypeAttributeValue => "signedAttrContentTypeAttributeValue".into(),
            SignerInfoSignedAttributeMessageDigest => "signedAttrMessageDigest".into(),
            SignerInfoSignedAttributeMessageDigestOid => "signedAttrMessageDigestOid".into(),
            SignerInfoSignedAttributeMessageDigestValues => "signedAttrMessageDigestValues".into(),
            SignerInfoSignedAttributeMessageDigestAttributeValue => "signedAttrMessageDigestAttributeValue".into(),
            SignerInfoSignedAttributeSigningTime => "signedAttrSigningTime".into(),
            SignerInfoSignedAttributeSigningTimeOid => "signedAttrSigningTimeOid".into(),
            SignerInfoSignedAttributeSigningTimeValues => "signedAttrSigningTimeValues".into(),
            SignerInfoSignedAttributeSigningTimeAttributeValue => "signedAttrSigningTimeAttributeValue".into(),
            SignerInfoSignedAttributeBinarySigningTime => "signedAttrBinarySigningTime".into(),
            SignerInfoSignedAttributeBinarySigningTimeOid => "signedAttrBinarySigningTimeOid".into(),
            SignerInfoSignedAttributeBinarySigningTimeValues => "signedAttrBinarySigningTimeValues".into(),
            SignerInfoSignedAttributeBinarySigningTimeAttributeValue => "signedAttrBinarySigningTimeAttributeValue".into(),
            SignerInfoSignedAttributeSignature => "signedAttrSignature".into(),
            SignerInfoSignedAttributeSignatureOid => "signedAttrSignatureOid".into(),
            SignerInfoSignedAttributeSignatureValues => "signedAttrSignatureValues".into(),
            SignerInfoSignedAttributeSignatureAttributeValue => "signedAttrSignatureAttributeValue".into(),
            SignerInfoSignatureAlgorithm => "signerInfoSignatureAlgorithm".into(),
            SignerInfoSignatureAlgorithmId => "signerInfoSignatureAlgorithmId".into(),
            SignerInfoSignatureAlgorithmParameters => "signerInfoSignatureAlgorithmParameters".into(),
            SignerInfoSignature => "signerInfoSignature".into(),

            Custom(label) => label.clone(),
        }
    }

    /// Returns the OID associated with a [`LabelName`] (indicated by ending with -Oid).
    ///
    /// Returns [`None`], if no OID is associated with this [`LabelName`].
    pub fn oid(&self) -> Option<&'static str> {
        use LabelName::*;
        match self {
            CertExtAkiOid => Some("2.5.29.35"),
            CertExtSkiOid => Some("2.5.29.14"),
            CertExtKuOid => Some("2.5.29.15"),
            CertExtCpOid => Some("2.5.29.32"),
            CertExtBcOid => Some("2.5.29.19"),
            CertExtCrldpOid => Some("2.5.29.31"),
            CertExtAiaOid => Some("1.3.6.1.5.5.7.1.1"),
            CertExtAiaCaIssuersOid => Some("1.3.6.1.5.5.7.48.2"),
            CertExtSiaOid => Some("1.3.6.1.5.5.7.1.11"),
            CertExtSiaCaRepositoryOid => Some("1.3.6.1.5.5.7.48.5"),
            CertExtSiaRpkiManifestOid => Some("1.3.6.1.5.5.7.48.10"),
            CertExtSiaNotificationOid => Some("1.3.6.1.5.5.7.48.13"),
            CertExtSiaSignedObjectOid => Some("1.3.6.1.5.5.7.48.11"),
            CertExtIpOid => Some("1.3.6.1.5.5.7.1.7"),
            CertExtAsidOid => Some("1.3.6.1.5.5.7.1.8"),
            CrlExtCrlnOid => Some("2.5.29.20"),
            SignerInfoSignedAttributeContentTypeOid => Some("1.2.840.113549.1.9.3"),
            SignerInfoSignedAttributeMessageDigestOid => Some("1.2.840.113549.1.9.4"),
            SignerInfoSignedAttributeSigningTimeOid => Some("1.2.840.113549.1.9.5"),
            SignerInfoSignedAttributeBinarySigningTimeOid => Some("1.2.840.113549.1.9.16.2.46"),
            SignerInfoSignedAttributeSignatureOid => Some("1.2.840.113549.1.9.6"),
            _ => None,
        }
    }
}