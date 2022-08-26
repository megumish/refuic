use refuic_common::EndpointType;
use refuic_tls::handshake::{client_hello::ClientHelloData, server_hello::ServerHelloData};

use crate::LongHeaderPacket;

use super::{
    endpoint_server::{ServerInitialPacket, ServerInitialPacketRfc9000},
    InitialPacketRfc9000, ProtectError,
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

    pub fn server_initial(
        &self,
        client_hello_data: &ClientHelloData,
        server_key: &[u8],
    ) -> ServerInitialPacket {
        match self {
            Self::Rfc9000(p) => p.server_initial(client_hello_data, server_key),
        }
    }

    pub fn protect(&self) -> Result<LongHeaderPacket, ProtectError> {
        match self {
            Self::Rfc9000(p) => p.0.protect(&EndpointType::Client),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ClientInitialPacketRfc9000(InitialPacketRfc9000);

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
