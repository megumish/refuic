// Only TLS 1.3
#[derive(Debug, PartialEq, Clone)]
pub enum NamedCurve {
    Deprecated(u16),
    Reserved(u16),
    Secp256r1,
    Secp384rl,
    Secp521r1,
    X25519,
    X448,
    Others(u16),
}

impl NamedCurve {
    pub fn to_bytes(&self) -> [u8; 2] {
        match self {
            Self::X25519 => [0x00, 0x1D],
            _ => unimplemented!(),
        }
    }

    pub fn len(&self) -> usize {
        2
    }

    pub fn from_u16(u: u16) -> Self {
        match u {
            0x17 => Self::Secp256r1,
            0x18 => Self::Secp384rl,
            0x1d => Self::X25519,
            x => Self::Others(x),
        }
    }
}
