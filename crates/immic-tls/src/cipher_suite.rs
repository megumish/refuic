#[derive(Debug, PartialEq, Clone)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChaCha30Poly1305Sha256,
    TlsAes128CcmSha256,
    TlsAes128Ccm8Sha256,
    Others(Vec<u8>),
}

impl CipherSuite {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            [0x13, 0x01] => Self::TlsAes128GcmSha256,
            [0x13, 0x02] => Self::TlsAes256GcmSha384,
            [0x13, 0x03] => Self::TlsChaCha30Poly1305Sha256,
            [0x13, 0x04] => Self::TlsAes128CcmSha256,
            [0x13, 0x05] => Self::TlsAes128Ccm8Sha256,
            x => Self::Others(x.to_owned()),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::TlsAes128GcmSha256 => vec![0x13, 0x01],
            Self::TlsAes256GcmSha384 => vec![0x13, 0x02],
            Self::TlsChaCha30Poly1305Sha256 => vec![0x13, 0x03],
            Self::TlsAes128CcmSha256 => vec![0x13, 0x04],
            Self::TlsAes128Ccm8Sha256 => vec![0x13, 0x05],
            Self::Others(x) => x.clone(),
        }
    }
}
