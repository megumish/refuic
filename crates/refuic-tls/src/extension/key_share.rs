use crate::named_curve::NamedCurve;

#[derive(Debug, PartialEq, Clone)]
pub enum Extension {
    Server(KeyShareEntry),
}

#[derive(Debug, PartialEq, Clone)]
pub struct KeyShareEntry {
    named_group: NamedCurve,
    key_exchange: Vec<u8>,
}

impl Extension {
    pub fn new_x25519_server(key: &[u8]) -> super::Extension {
        super::Extension::KeyShare(Self::Server(KeyShareEntry {
            named_group: NamedCurve::X25519,
            key_exchange: key.to_vec(),
        }))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Server(e) => [
                &e.named_group.to_bytes(),
                &(e.key_exchange.len() as u16).to_be_bytes(),
                &e.key_exchange[..],
            ]
            .concat(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Server(e) => e.named_group.len() + 2 + e.key_exchange.len(),
        }
    }
}
