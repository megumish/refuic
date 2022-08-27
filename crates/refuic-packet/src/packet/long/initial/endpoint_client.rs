use refuic_common::{EndpointType, QuicVersion};
use refuic_tls::handshake::{client_hello::ClientHelloData, server_hello::ServerHelloData};

use crate::LongHeaderPacket;

use super::{
    endpoint_server::{ServerInitialPacket, ServerInitialPacketRfc9000},
    InitialPacketRfc9000, ProtectError, UnprotectError,
};

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

    pub fn server_initial(
        &self,
        client_hello_data: &ClientHelloData,
        server_key: &[u8],
    ) -> ServerInitialPacket {
        match self {
            Self::Rfc9000(p) => p.server_initial(client_hello_data, server_key),
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
    ) -> Result<ClientInitialPacket, UnprotectError> {
        match version {
            QuicVersion::Rfc9000 => Ok(ClientInitialPacket::Rfc9000(ClientInitialPacketRfc9000(
                InitialPacketRfc9000::unprotect(
                    initial_destination_connection_id,
                    packet,
                    my_endpoint_type,
                )?,
            ))),
            _ => Err(UnprotectError::NoSupportVersion),
        }
    }

    pub fn parse_from_bytes(
        buf: &[u8],
        initial_destination_connection_id: &[u8],
        version: &QuicVersion,
        my_endpoint_type: &EndpointType,
    ) -> Result<ClientInitialPacket, ParseFromBytesError> {
        let long = crate::long::parse_from_bytes(buf, version)?;
        Ok(ClientInitialPacket::Rfc9000(ClientInitialPacketRfc9000(
            InitialPacketRfc9000::unprotect(
                initial_destination_connection_id,
                &long,
                my_endpoint_type,
            )?,
        )))
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
    fn server_initial(
        &self,
        client_hello_data: &ClientHelloData,
        server_key: &[u8],
    ) -> ServerInitialPacket {
        let source_connection_id = self.0.destination_connection_id.clone();
        let destination_connection_id = self.0.source_connection_id.clone();

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2.1
        // The value included prior to protection MUST be set to 0
        // プロテクションされる前の値は0でなければならない
        let reserved_bits = [false, false];
        let version = self.0.version.clone();

        // TokenはRetry PacketかNew Token Frameを受け取った時しか使わない
        // のでここでは空にしておく
        let token = Vec::new();

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3-10
        // A QUIC endpoint MUST NOT reuse a packet number within the same packet number space in one connection.
        // らしいので、とりあえずパケットごとに一つずつ増やしてみる
        let packet_number = self.0.packet_number + 1;

        let payload = {
            let tls_server_hello = ServerHelloData::new(client_hello_data, server_key);
            let crypto_frame = refuic_frame::frame::crypto::Frame::new(tls_server_hello.to_vec());
            let ack_frame = refuic_frame::frame::ack::Frame::new(packet_number - 1);
            let mut payload = Vec::new();
            payload.extend(crypto_frame.to_vec());
            payload.extend(ack_frame.to_vec());
            payload.extend(vec![0u8; 1200 - payload.len()]);
            payload
        };

        ServerInitialPacket::Rfc9000(ServerInitialPacketRfc9000(InitialPacketRfc9000 {
            reserved_bits,
            version,
            destination_connection_id,
            source_connection_id,
            token,
            packet_number,
            payload,
        }))
    }
}
