#[derive(Debug, PartialEq, Clone)]
pub enum Extension {
    Server([u8; 2]),
    Client(Vec<[u8; 2]>),
}

impl Extension {
    // > This document describes TLS 1.3, which uses the version 0x0304.
    pub fn new_only_tls13_server() -> super::Extension {
        super::Extension::SupportedVersions(Self::Server([0x03, 0x04]))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Server(v) => v.to_vec(),
            Self::Client(vs) => [
                &(vs.clone().len() as u8).to_be_bytes()[..],
                &vs.clone().into_iter().flatten().collect::<Vec<u8>>(),
            ]
            .concat(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Server(_) => 2,
            Self::Client(v) => 1 + v.len() * 2,
        }
    }
}
