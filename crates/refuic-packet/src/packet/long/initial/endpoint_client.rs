use rand::{rngs::StdRng, Fill, SeedableRng};
use refuic_common::{EndpointType, QuicVersion};

use crate::{packet_number::PacketNumber, LongHeaderPacket};

use super::{InitialPacketRfc9000, ProtectError, UnprotectError};

#[derive(Debug, PartialEq, Clone)]
pub enum ClientInitialPacket {
    Rfc9000(ClientInitialPacketRfc9000),
}

impl ClientInitialPacket {
    pub fn payload<'a>(&'a self) -> &'a Vec<u8> {
        match self {
            Self::Rfc9000(p) => p.0.payload(),
        }
    }

    pub fn destination_connection_id<'a>(&'a self) -> &'a Vec<u8> {
        match self {
            Self::Rfc9000(p) => p.0.destination_connection_id(),
        }
    }

    pub fn source_connection_id<'a>(&'a self) -> &'a Vec<u8> {
        match self {
            Self::Rfc9000(p) => p.0.source_connection_id(),
        }
    }

    pub fn new_hello(
        version: &QuicVersion,
        packet_number: &PacketNumber,
        initial_destination_connection_id: Option<&[u8]>,
    ) -> Result<Self, NewHelloError> {
        match version {
            QuicVersion::Rfc9000 => ClientInitialPacketRfc9000::new_hello(
                packet_number,
                initial_destination_connection_id,
            ),
            _ => Err(NewHelloError::NoSupportVersion),
        }
    }

    pub fn protect(
        &self,
        initial_destination_connection_id: &[u8],
    ) -> Result<LongHeaderPacket, ProtectError> {
        match self {
            Self::Rfc9000(p) => {
                p.0.protect(initial_destination_connection_id, &EndpointType::Client)
            }
        }
    }

    pub fn unprotect(
        packet: &LongHeaderPacket,
        initial_destination_connection_id: &[u8],
        version: &QuicVersion,
        my_endpoint_type: &EndpointType,
    ) -> Result<(ClientInitialPacket, usize), UnprotectError> {
        match version {
            QuicVersion::Rfc9000 => {
                let (p, len) = InitialPacketRfc9000::unprotect(
                    initial_destination_connection_id,
                    packet,
                    my_endpoint_type,
                )?;
                Ok((
                    ClientInitialPacket::Rfc9000(ClientInitialPacketRfc9000(p)),
                    len,
                ))
            }
            _ => Err(UnprotectError::NoSupportVersion),
        }
    }

    pub fn parse_from_bytes(
        buf: &[u8],
        initial_destination_connection_id: &[u8],
        version: &QuicVersion,
        my_endpoint_type: &EndpointType,
    ) -> Result<(ClientInitialPacket, usize), ParseFromBytesError> {
        let long = crate::long::parse_from_bytes(buf, version)?;
        let (p, len) = InitialPacketRfc9000::unprotect(
            initial_destination_connection_id,
            &long,
            my_endpoint_type,
        )?;
        Ok((
            ClientInitialPacket::Rfc9000(ClientInitialPacketRfc9000(p)),
            len,
        ))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ClientInitialPacketRfc9000(InitialPacketRfc9000);

#[derive(thiserror::Error, Debug)]
pub enum ParseFromBytesError {
    #[error("parse from bytes to long")]
    ParseFromBytesToLong(#[from] crate::long::ParseFromBytesError),
    #[error("unprotect error")]
    UnprotectError(#[from] super::UnprotectError),
}

impl ClientInitialPacketRfc9000 {
    fn new_hello(
        packet_number: &PacketNumber,
        initial_destination_connection_id: Option<&[u8]>,
    ) -> Result<ClientInitialPacket, NewHelloError> {
        let mut random_generator = StdRng::from_entropy();

        let source_connection_id = {
            let mut buf = [0; 20];
            buf.try_fill(&mut random_generator)?;
            buf.to_vec()
        };
        let destination_connection_id = if let Some(id) = initial_destination_connection_id {
            id.to_vec()
        } else {
            let mut buf = [0; 20];
            buf.try_fill(&mut random_generator)?;
            buf.to_vec()
        };

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2.1
        // The value included prior to protection MUST be set to 0
        // ??????????????????????????????????????????0???????????????????????????
        let reserved_bits = [false, false];

        // Token???Retry Packet???New Token Frame???????????????????????????????????????
        // ????????????????????????????????????
        let token = Vec::new();

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3-10
        // A QUIC endpoint MUST NOT reuse a packet number within the same packet number space in one connection.
        // ????????????????????????????????????????????????????????????????????????????????????
        let packet_number = packet_number.next().u32();

        let payload = {
            let mut payload = Vec::new();
            payload.extend(vec![0u8; 1200 - payload.len()]);
            payload
        };

        Ok(ClientInitialPacket::Rfc9000(ClientInitialPacketRfc9000(
            InitialPacketRfc9000 {
                reserved_bits,
                destination_connection_id,
                source_connection_id,
                token,
                packet_number,
                payload,
            },
        )))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NewHelloError {
    #[error("no support version")]
    NoSupportVersion,
    #[error("random value generation error")]
    RandomValueGenerationError(#[from] rand::Error),
}
