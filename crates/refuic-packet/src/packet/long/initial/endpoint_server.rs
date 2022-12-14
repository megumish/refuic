use refuic_common::{EndpointType, QuicVersion};
use refuic_tls::{
    cipher_suite::CipherSuite,
    extension::{key_share::KeyShareEntry, supported_versions::Version},
    handshake::server_hello::ServerHelloData,
};

use crate::{packet_number::PacketNumber, LongHeaderPacket};

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

    pub fn new_hello(
        version: &QuicVersion,
        packet_number: &PacketNumber,
        source_connection_id: &[u8],
        destination_connection_id: &[u8],
        cipher_suite: &CipherSuite,
        server_key_share_entry: &KeyShareEntry,
        supported_version: &Version,
    ) -> Result<(Self, ServerHelloData), NewHelloError> {
        match version {
            QuicVersion::Rfc9000 => Ok(ServerInitialPacketRfc9000::new_hello(
                source_connection_id,
                destination_connection_id,
                packet_number,
                cipher_suite,
                server_key_share_entry,
                supported_version,
            )),
            _ => Err(NewHelloError::NoSupportVersion),
        }
    }

    pub fn protect(
        &self,
        initial_destination_connection_id: &[u8],
    ) -> Result<LongHeaderPacket, ProtectError> {
        match self {
            Self::Rfc9000(p) => {
                p.0.protect(initial_destination_connection_id, &EndpointType::Server)
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ServerInitialPacketRfc9000(pub(super) InitialPacketRfc9000);

impl ServerInitialPacketRfc9000 {
    fn payload<'a>(&'a self) -> &'a Vec<u8> {
        &self.0.payload
    }

    pub fn new_hello(
        source_connection_id: &[u8],
        destination_connection_id: &[u8],
        packet_number: &PacketNumber,
        cipher_suite: &CipherSuite,
        server_key_share_entry: &KeyShareEntry,
        supported_version: &Version,
    ) -> (ServerInitialPacket, ServerHelloData) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2.1
        // The value included prior to protection MUST be set to 0
        // ??????????????????????????????????????????0???????????????????????????
        let reserved_bits = [false, false];

        // Token???Retry Packet???New Token Frame???????????????????????????????????????
        // ????????????????????????????????????
        let token = Vec::new();

        let (payload, tls_server_hello) = {
            let tls_server_hello =
                ServerHelloData::new(cipher_suite, &[], server_key_share_entry, supported_version);
            let crypto_frame = refuic_frame::frame::crypto::Frame::new(tls_server_hello.to_vec());
            let ack_frame = refuic_frame::frame::ack::Frame::new(packet_number.u32());
            let mut payload = Vec::new();
            payload.extend(crypto_frame.to_vec());
            payload.extend(ack_frame.to_vec());
            payload.extend(vec![0u8; 1200 - payload.len()]);
            (payload, tls_server_hello)
        };

        (
            ServerInitialPacket::Rfc9000(ServerInitialPacketRfc9000(InitialPacketRfc9000 {
                reserved_bits,
                destination_connection_id: destination_connection_id.to_vec(),
                source_connection_id: source_connection_id.to_vec(),
                token,
                packet_number: packet_number.u32(),
                payload,
            })),
            tls_server_hello,
        )
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NewHelloError {
    #[error("no support version")]
    NoSupportVersion,
}
