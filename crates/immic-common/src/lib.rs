use tracing::instrument;

pub mod var_int;

pub use var_int::ReadVarInt;

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
