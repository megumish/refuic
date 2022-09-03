use std::net::SocketAddr;

use connection::{
    ConnectionMap, ConnectionRfc9000, FetchConnectionError, NewConnectionError,
    UpdateConnectionError,
};
use refuic_common::{EndpointType, QuicVersion};
use refuic_frame::frame::{
    self, crypto::read_crypto_frame, parse_from_bytes_v1, FrameRfc9000, ParseFrameError,
};
use refuic_packet::{
    long::{
        self,
        initial::{ClientInitialPacket, UnprotectError},
    },
    LongHeaderPacket,
};
use refuic_tls::{
    cipher_suite::CipherSuite, extension::Extension, handshake::HandshakeTransformError,
};
use socket::Socket;

mod connection;
mod context;
mod socket;
mod space;

pub struct Endpoint<C, S>
where
    C: ConnectionMap,
    S: Socket,
{
    connection_map: C,
    socket: S,
    endpoint_type: EndpointType,
}

impl<C, S> Endpoint<C, S>
where
    C: ConnectionMap,
    S: Socket,
{
    // 受け取ったメッセージと相手のコネクションIDを返す
    async fn recv(&mut self) -> Result<(Vec<u8>, Vec<u8>), RecvError> {
        let mut buf = Vec::new();
        loop {
            let (new_buf, socket_address) = {
                // UDPデータグラムに入る最小のバイト数は1200であるので
                // バッファーもとりあえずは1200以上の値にしておく
                let mut buf = [0; 2048];
                let (length, addr) = self.socket.recv_from(&mut buf).await?;
                (buf[0..length].to_owned(), addr)
            };
            buf.extend(new_buf);

            match long::parse_from_bytes(&buf, &QuicVersion::Rfc9000) {
                Err(long::ParseFromBytesError::NotLongPacket) => { /* do nothing */ }
                Err(long::ParseFromBytesError::UnexpectedEnd) => continue,
                Err(long::ParseFromBytesError::NoSupportVersion) => {
                    unimplemented!("recv no support version packet")
                }
                Err(e) => return Err(e).map_err(Into::into),
                Ok(p) => {
                    if p.version() == &QuicVersion::Rfc9000 {
                        let connection = self
                            .connection_map
                            .connection_v1(p.destination_connection_id())?;
                        let connection = if let Some(connection) = connection {
                            connection
                        } else {
                            let connection = self
                                .connection_map
                                .new_connection_v1(p.destination_connection_id(), socket_address)?;
                            connection
                        };
                        if connection.is_after_handshake_done() {
                            unimplemented!("reach after handshake world!")
                        }
                        if connection.is_after_hello() {
                            unimplemented!("reach after hello world!")
                        }
                        match self.hello_v1(connection, &p, &socket_address) {
                            Err(HelloError::NotInitialPacket) => { /* do nothing */ }
                            Err(HelloError::UnexpectedEnd) => continue,
                            Err(HelloError::NoSupportVersion) => {
                                unimplemented!("recv no support version packet")
                            }
                            Err(e) => return Err(e).map_err(Into::into),
                            Ok(packet_length) => {
                                // bufを消費して次のパケットに進む
                                let _ = buf.drain(..packet_length);
                                continue;
                            }
                        }
                    }
                }
            }

            unimplemented!("reach short message!")
        }
        Ok((Vec::new(), Vec::new()))
    }

    fn hello_v1(
        &self,
        connection: &ConnectionRfc9000,
        packet: &LongHeaderPacket,
        socket_address: &SocketAddr,
    ) -> Result<usize, HelloError> {
        match self.endpoint_type {
            // Server は ClientHello を受け取る
            EndpointType::Server => self.client_hello_v1(connection, packet, socket_address),
            // Client は ServerHello を受け取る
            EndpointType::Client => self.server_hello_v1(connection, packet, socket_address),
        }
    }

    pub fn client_hello_v1(
        &self,
        connection: &ConnectionRfc9000,
        packet: &LongHeaderPacket,
        socket_address: &SocketAddr,
    ) -> Result<usize, HelloError> {
        let initial_destination_connection_id =
            if let Some(id) = connection.initial_destination_connection_id() {
                id
            } else {
                packet.destination_connection_id()
            };
        let (client_initial, original_length) = match ClientInitialPacket::unprotect(
            packet,
            initial_destination_connection_id,
            &QuicVersion::Rfc9000,
            &self.endpoint_type,
        ) {
            Err(UnprotectError::NotInitialPacket) => return Err(HelloError::NotInitialPacket),
            Err(UnprotectError::UnexpectedEnd) => return Err(HelloError::UnexpectedEnd),
            Err(UnprotectError::NoSupportVersion) => return Err(HelloError::NoSupportVersion),
            Err(e) => return Err(e).map_err(Into::into),
            Ok(p) => p,
        };
        self.save_client_initial_v1(&client_initial)?;
        self.send_server_hello_v1_event(socket_address, initial_destination_connection_id)?;
        // protectを外した後ではなく、元のパケットの大きさを返す
        Ok(original_length)
    }

    fn save_client_initial_v1(
        &self,
        client_initial: &ClientInitialPacket,
    ) -> Result<(), SavePacketError> {
        let frames = frame::parse_from_bytes_v1(client_initial.payload())?;
        for frame in frames {
            match frame {
                // Crypto Frameのオフセットは考慮しない
                FrameRfc9000::Crypto(f) => {
                    match refuic_tls::handshake::client_hello::parse_from_bytes(f.crypto_data()) {
                        Err(e) => return Err(e).map_err(Into::into),
                        Ok(client_hello_data) => {
                            let cipher_suites = client_hello_data.cipher_suites();
                            self.save_cipher_suites_v1(
                                cipher_suites,
                                client_initial.destination_connection_id(),
                            )?;
                            let extensions = client_hello_data.extensions();
                            self.save_tls_extensions_v1(
                                extensions,
                                client_initial.destination_connection_id(),
                            )?;
                        }
                    }
                }
                _ => unimplemented!(),
            }
        }
        Ok(())
    }

    fn save_cipher_suites_v1(
        &self,
        cipher_suites: &[CipherSuite],
        connection_id: &[u8],
    ) -> Result<(), SavePacketError> {
        self.connection_map
            .update_cipher_suites_v1(connection_id, cipher_suites)?;
        Ok(())
    }

    fn save_tls_extensions_v1(
        &self,
        extensions: &[Extension],
        connection_id: &[u8],
    ) -> Result<(), SavePacketError> {
        for extension in extensions {
            match extension {
                Extension::ServerName(e) => {
                    // TOOD: 保存する処理
                }
                Extension::SupportedGroups(e) => {
                    self.connection_map
                        .insert_client_named_curves_v1(connection_id, e.named_curves());
                }
                _ => { /* do nothing */ }
            }
        }
        Ok(())
    }

    fn send_server_hello_v1_event(
        &self,
        socket_address: &SocketAddr,
        initial_destination_connection_id: &[u8],
    ) -> Result<(), PushEventError> {
        todo!()
    }

    fn server_hello_v1(
        &self,
        connection: &ConnectionRfc9000,
        packet: &LongHeaderPacket,
        socket_address: &SocketAddr,
    ) -> Result<usize, HelloError> {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BindError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum RecvError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
    #[error("parse long packet from bytes")]
    LongPacketFromBytesError(#[from] long::ParseFromBytesError),
    #[error("hello error")]
    HelloError(#[from] HelloError),
    #[error("socket error")]
    SocketError(#[from] socket::RecvError),
    #[error("update connection error")]
    NewConnectionError(#[from] NewConnectionError),
    #[error("fetch connection error")]
    FetchConnectionError(#[from] FetchConnectionError),
}

#[derive(thiserror::Error, Debug)]
pub enum HelloError {
    #[error("unexpected end")]
    UnexpectedEnd,
    #[error("no support version error")]
    NoSupportVersion,
    #[error("not initial packet")]
    NotInitialPacket,

    #[error("unprotect error")]
    UnprotectError(#[from] UnprotectError),
    #[error("save packet error")]
    SavePacketError(#[from] SavePacketError),
    #[error("push event error")]
    PushEventError(#[from] PushEventError),
}

#[derive(thiserror::Error, Debug)]
pub enum SavePacketError {
    #[error("parse frame error")]
    ParseFrameError(#[from] ParseFrameError),
    #[error("handshake transform error")]
    HandshakeTransformError(#[from] HandshakeTransformError),
    #[error("update connection error")]
    UpdateConnectionError(#[from] UpdateConnectionError),
}

#[derive(thiserror::Error, Debug)]
pub enum PushEventError {}

#[cfg(test)]
mod tests;
