use refuic_common::EndpointType;

use crate::LongHeaderPacket;

use super::{InitialPacketRfc9000, ProtectError};

#[derive(Debug, PartialEq, Clone)]
pub enum ServerInitialPacket {
    Rfc9000(ServerInitialPacketRfc9000),
}

impl ServerInitialPacket {
    pub fn payload<'a>(&'a self) -> &'a Vec<u8> {
        match self {
            Self::Rfc9000(p) => p.payload(),
        }
    }

    pub fn protect(&self) -> Result<LongHeaderPacket, ProtectError> {
        match self {
            Self::Rfc9000(p) => p.0.protect(&EndpointType::Server),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ServerInitialPacketRfc9000(pub(super) InitialPacketRfc9000);

impl ServerInitialPacketRfc9000 {
    fn payload<'a>(&'a self) -> &'a Vec<u8> {
        &self.0.payload
    }
}
