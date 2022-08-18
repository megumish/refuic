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
}
