use std::net::SocketAddr;

use app::AppRepository;
use connection::ConnectionRepository;
use crypto_kit::CryptoKitRepository;
use refuic_common::{EndpointType, QuicVersion};
use refuic_frame::frame::{self, FrameRfc9000, ParseFrameError};
use refuic_packet::{
    long::{
        self,
        initial::{ClientInitialPacket, UnprotectError},
    },
    LongHeaderPacket,
};
use refuic_tls::{
    cipher_suite::CipherSuite,
    extension::{key_share, supported_versions, Extension},
    handshake::HandshakeTransformError,
};
use socket::Socket;
use transport_parameter::TransportParameterRepository;

mod app;
mod connection;
mod crypto_kit;
mod repository;
mod socket;
mod space;
mod transport_parameter;

pub struct Endpoint<Conn, Crypto, App, Trans, S>
where
    Conn: ConnectionRepository,
    Crypto: CryptoKitRepository,
    App: AppRepository,
    Trans: TransportParameterRepository,
    S: Socket,
{
    connection_repository: Conn,
    crypto_kit_repository: Crypto,
    app_repository: App,
    transport_parameter_repository: Trans,
    socket: S,
    endpoint_type: EndpointType,
}

impl<Conn, Crypto, App, Trans, S> Endpoint<Conn, Crypto, App, Trans, S>
where
    Conn: ConnectionRepository,
    Crypto: CryptoKitRepository,
    App: AppRepository,
    Trans: TransportParameterRepository,
    S: Socket,
{
    // 受け取ったメッセージと相手のコネクションIDを返す
    pub async fn recv(&mut self) -> Result<(Vec<u8>, Vec<u8>), RecvError> {
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
                        if self.is_after_handshake_done(p.destination_connection_id())? {
                            unimplemented!("reach after handshake world!")
                        }
                        match self.hello_v1(p.destination_connection_id(), &p, &socket_address) {
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
    }

    fn is_after_handshake_done(
        &self,
        connection_id: &[u8],
    ) -> Result<bool, IsAfterHandshakeDoneError> {
        Ok(self
            .crypto_kit_repository
            .is_negotiated_cipher_suite_v1(connection_id)?
            & self
                .crypto_kit_repository
                .is_negotiated_server_name_v1(connection_id)?
            & self
                .crypto_kit_repository
                .is_negotiated_named_curve_v1(connection_id)?
            & self
                .crypto_kit_repository
                .is_negotiated_signature_algorithm_v1(connection_id)?
            & self
                .crypto_kit_repository
                .is_negotiated_client_key_share_v1(connection_id)?
            & self
                .crypto_kit_repository
                .is_negotiated_psk_key_exchange_mode_v1(connection_id)?
            & self
                .crypto_kit_repository
                .is_negotiated_supported_version_v1(connection_id)?
            & self
                .connection_repository
                .is_acknowlegded_hello(connection_id)?)
    }

    fn hello_v1(
        &self,
        connection_id: &[u8],
        packet: &LongHeaderPacket,
        socket_address: &SocketAddr,
    ) -> Result<usize, HelloError> {
        match self.endpoint_type {
            // Server は ClientHello を受け取る
            EndpointType::Server => self.client_hello_v1(connection_id, packet, socket_address),
            // Client は ServerHello を受け取る
            EndpointType::Client => self.server_hello_v1(connection_id, packet, socket_address),
        }
    }

    pub fn client_hello_v1(
        &self,
        connection_id: &[u8],
        packet: &LongHeaderPacket,
        socket_address: &SocketAddr,
    ) -> Result<usize, HelloError> {
        let (client_initial, original_length) = match ClientInitialPacket::unprotect(
            packet,
            connection_id,
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
        self.send_server_hello_v1(socket_address, connection_id)?;
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
        self.crypto_kit_repository
            .update_client_cipher_suites_v1(connection_id, cipher_suites)?;
        Ok(())
    }

    fn save_tls_extensions_v1(
        &self,
        extensions: &[Extension],
        connection_id: &[u8],
    ) -> Result<(), SavePacketError> {
        for extension in extensions {
            match extension {
                Extension::ServerName(e) => self
                    .crypto_kit_repository
                    .update_client_server_names_v1(connection_id, e.server_names())?,
                Extension::SupportedGroups(e) => {
                    self.crypto_kit_repository
                        .update_client_named_curves_v1(connection_id, e.named_curves())?;
                }
                Extension::Alpn(e) => {
                    self.app_repository
                        .update_client_app_protocols_v1(connection_id, e.protocol_names())?;
                }
                Extension::SignatureAlgorithms(e) => self
                    .crypto_kit_repository
                    .update_client_signature_algorithms_v1(connection_id, e.signature_schemes())?,
                Extension::KeyShare(e) => match e {
                    key_share::Extension::Server {
                        entry: _,
                        length: _,
                    } => {
                        unreachable!("reading client initial, but found server hello info")
                    }
                    key_share::Extension::Client { entries, length: _ } => self
                        .crypto_kit_repository
                        .update_client_key_share_v1(connection_id, entries)?,
                },
                Extension::PskKeyExchangeModes(e) => {
                    self.crypto_kit_repository
                        .update_client_psk_key_exchange_modes_v1(connection_id, e.modes())?;
                }
                Extension::SupportedVersions(e) => match e {
                    supported_versions::Extension::Server(_) => {
                        unreachable!("reading client initial, but found server hello info")
                    }
                    supported_versions::Extension::Client {
                        versions,
                        length: _,
                    } => self
                        .crypto_kit_repository
                        .update_client_supported_versions_v1(connection_id, versions)?,
                },
                Extension::QuicTransportParameters(e) => self
                    .transport_parameter_repository
                    .update_client_transport_parameters_v1(connection_id, e.parameters())?,
                _ => { /* do nothing */ }
            }
        }
        Ok(())
    }

    fn send_server_hello_v1(
        &self,
        _socket_address: &SocketAddr,
        _initial_destination_connection_id: &[u8],
    ) -> Result<(), PushEventError> {
        todo!()
    }

    fn server_hello_v1(
        &self,
        _connection: &[u8],
        _packet: &LongHeaderPacket,
        _socket_address: &SocketAddr,
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
    #[error("is after handshake done error")]
    IsAfterHandshakeDoneError(#[from] IsAfterHandshakeDoneError),
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
    #[error("repository error")]
    RepositoryError(#[from] repository::RepositoryError),
}

#[derive(thiserror::Error, Debug)]
pub enum IsAfterHandshakeDoneError {
    #[error("repository error")]
    RepositoryError(#[from] repository::RepositoryError),
}

#[derive(thiserror::Error, Debug)]
pub enum PushEventError {}
