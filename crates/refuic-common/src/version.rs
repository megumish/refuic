use tracing::instrument;

#[derive(Debug, Clone, PartialEq)]
pub enum QuicVersion {
    Rfc9000,
    VersionNegotiation,
    Others(u32),
}

impl QuicVersion {
    #[instrument(ret, name = "get initial salt", level = "trace")]
    pub fn initial_salt(&self) -> [u8; 0x14] {
        match self {
            QuicVersion::Rfc9000 => [
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            _ => unimplemented!(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        match self {
            QuicVersion::Rfc9000 => [0, 0, 0, 1],
            QuicVersion::VersionNegotiation => [0, 0, 0, 0],
            QuicVersion::Others(x) => x.to_le_bytes(),
        }
    }

    pub fn len(&self) -> usize {
        4
    }
}

impl Into<QuicVersion> for u32 {
    #[instrument(ret, name = "u32 to QuicVersion", level = "trace")]
    fn into(self) -> QuicVersion {
        match self {
            0x00000000 => QuicVersion::VersionNegotiation,
            0x00000001 => QuicVersion::Rfc9000,
            x => QuicVersion::Others(x),
        }
    }
}
