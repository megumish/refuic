use spki::ObjectIdentifier;

#[allow(unused)]
#[derive(Debug, PartialEq, Clone)]
pub enum SignatureScheme {
    // RSASSA-PKCS1-v1_5
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    // ECDSA
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp521r1Sha512,
    // RSASSA-PSS with public key OID rsaEncryption
    RsaPssRsaeSha256,
    RsaPssRsaeSha384,
    RsaPssRsaeSha512,
    // EdDSA
    Ed25519,
    Ed448,
    // RSASSA-PSS with public key OID RSASSA-PSS
    RsaPssPssSha256,
    RsaPssPssSha384,
    RsaPssPssSha512,
    // Legacy
    RsaPkcs1Sha1,
    EcdsaSha1,
    // Reserved
    PrivateUse(u16),

    Others(u16),
}

impl SignatureScheme {
    pub fn u16(&self) -> u16 {
        match self {
            SignatureScheme::RsaPkcs1Sha256 => 0x0401,
            SignatureScheme::RsaPkcs1Sha384 => 0x0501,
            SignatureScheme::RsaPkcs1Sha512 => 0x0601,
            SignatureScheme::EcdsaSecp256r1Sha256 => 0x0403,
            SignatureScheme::EcdsaSecp384r1Sha384 => 0x0503,
            SignatureScheme::EcdsaSecp521r1Sha512 => 0x0603,
            SignatureScheme::RsaPssRsaeSha256 => 0x0804,
            SignatureScheme::RsaPssRsaeSha384 => 0x0805,
            SignatureScheme::RsaPssRsaeSha512 => 0x0806,
            SignatureScheme::Ed25519 => 0x0807,
            SignatureScheme::Ed448 => 0x0808,
            SignatureScheme::RsaPssPssSha256 => 0x0809,
            SignatureScheme::RsaPssPssSha384 => 0x080a,
            SignatureScheme::RsaPssPssSha512 => 0x080b,
            SignatureScheme::RsaPkcs1Sha1 => 0x0201,
            SignatureScheme::EcdsaSha1 => 0x0203,
            SignatureScheme::PrivateUse(u) => *u,
            SignatureScheme::Others(u) => *u,
        }
    }

    pub fn from_oid(oid: &ObjectIdentifier) -> Option<SignatureScheme> {
        // https://oidref.com/1.2.840.113549.1.1.11
        if oid == &ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11") {
            Some(SignatureScheme::RsaPkcs1Sha256)
        // https://oidref.com/1.2.840.113549.1.1.12
        } else if oid == &ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12") {
            Some(SignatureScheme::RsaPkcs1Sha384)
        // TODO: 残りも後から埋める
        } else {
            None
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        self.u16().to_be_bytes()
    }

    pub fn len(&self) -> usize {
        2
    }
}
