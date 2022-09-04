use std::net::SocketAddr;

use app::{AppData, AppRepository};
use connection::ConnectionRepository;
use crypto_kit::{CryptoKit, CryptoKitRepository};
use refuic_common::{EndpointType, QuicVersion};
use refuic_frame::frame::{self, FrameRfc9000, ParseFrameError};
use refuic_packet::{
    long::{
        self,
        initial::{ClientInitialPacket, ServerInitialPacket, UnprotectError},
    },
    LongHeaderPacket,
};
use refuic_tls::{
    cipher_suite::CipherSuite,
    extension::{key_share, supported_versions, Extension},
    handshake::HandshakeTransformError,
};
use socket::Socket;
use transport_parameter::{TransportParameters, TransportParametersRepository};

use crate::repository::RepositoryError;

mod app;
mod connection;
mod crypto_kit;
pub mod implementation;
mod repository;
mod socket;
mod transport_parameter;

pub struct Endpoint<Conn, Crypto, App, Trans, S>
where
    Conn: ConnectionRepository,
    Crypto: CryptoKitRepository,
    App: AppRepository,
    Trans: TransportParametersRepository,
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
    Trans: TransportParametersRepository,
    S: Socket,
{
    // 受け取ったメッセージと相手のコネクションIDを返す
    pub fn recv(&mut self) -> Result<(Vec<u8>, Vec<u8>), RecvError> {
        let mut buf = Vec::new();
        loop {
            let (new_buf, socket_address) = {
                // UDPデータグラムに入る最小のバイト数は1200であるので
                // バッファーもとりあえずは1200以上の値にしておく
                let mut buf = [0; 2048];
                let (length, addr) = self.socket.recv_from(&mut buf)?;
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
                    tracing::debug!("recv long packet");
                    if p.version() == &QuicVersion::Rfc9000 {
                        match self.is_after_handshake_done_v1(p.destination_connection_id()) {
                            Ok(true) => unimplemented!("reach after handshake done"),
                            Ok(false) => { /* do nothing */ }
                            Err(JudgeError::RepositoryError(RepositoryError::NotFound)) => { /* do nothing */
                            }
                            Err(x) => return Err(x).map_err(Into::into),
                        }
                        match self.is_sent_server_hello(p.destination_connection_id()) {
                            Ok(true) => unimplemented!("reach after server hello sent"),
                            Ok(false) => { /* do nothing */ }
                            Err(JudgeError::RepositoryError(RepositoryError::NotFound)) => { /* do nothing */
                            }
                            Err(x) => return Err(x).map_err(Into::into),
                        }
                        match self.hello_v1(p.destination_connection_id(), &p, &socket_address) {
                            Err(HelloError::NotInitialPacket) => {
                                tracing::debug!("but not initial packet")
                            }
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
                        unimplemented!("reach otherwise client hello")
                    }
                }
            }

            unimplemented!("reach short message!")
        }
    }

    fn is_after_handshake_done_v1(&self, connection_id: &[u8]) -> Result<bool, JudgeError> {
        let connection = self.connection_repository.connection_v1(connection_id)?;
        Ok(self.is_sent_server_hello(connection_id)?
            && connection.is_acknowlegded_server_hello()
            && connection.is_acknowledged_encrypted_extensions()
            && connection.is_acknowledged_certificate()
            && connection.is_acknowledged_certificate_verify()
            && connection.is_acknowledged_handshake_finished())
    }

    fn is_sent_server_hello(&self, connection_id: &[u8]) -> Result<bool, JudgeError> {
        let connection = self.connection_repository.connection_v1(connection_id)?;
        Ok(self.is_prepared_server_hello(connection_id)?
            && connection.is_sent_server_hello()
            && connection.is_sent_encrypted_extensions()
            && connection.is_sent_certificate()
            && connection.is_sent_certificate_verify()
            && connection.is_sent_handshake_finished())
    }

    // ServerHelloを送信していいかどうかだけでなく、そのあとのHandshakePacketも送っていいのかも
    // これで判断する
    fn is_prepared_server_hello(&self, connection_id: &[u8]) -> Result<bool, JudgeError> {
        tracing::trace!("check prepared server hello");
        let crypto_kit = self.crypto_kit_repository.crypto_kit(connection_id)?;
        if !crypto_kit.is_negotiated_cipher_suite() {
            return Ok(false);
        }
        tracing::trace!("ok cipher suite");
        if !crypto_kit.is_negotiated_server_name() {
            return Ok(false);
        }
        tracing::trace!("ok server name");
        if !crypto_kit.is_negotiated_named_curve() {
            return Ok(false);
        }
        tracing::trace!("ok named curve");
        if !crypto_kit.is_negotiated_signature_algorithm() {
            return Ok(false);
        }
        tracing::trace!("ok signature algorithm");
        if !crypto_kit.is_negotiated_key_shares() {
            return Ok(false);
        }
        tracing::trace!("ok key shares");
        if !crypto_kit.is_negotiated_psk_key_exchange_mode() {
            return Ok(false);
        }
        tracing::trace!("ok psk key exchange mode");
        if !crypto_kit.is_negotiated_supported_version() {
            return Ok(false);
        }
        tracing::trace!("ok supported version");
        Ok(true)
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
                FrameRfc9000::Padding => { /* do nothing */ }
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
        let mut crypto_kit = match self.crypto_kit_repository.crypto_kit(connection_id) {
            Err(RepositoryError::NotFound) => CryptoKit::new(),
            Err(e) => return Err(e).map_err(Into::into),
            Ok(c) => c,
        };
        crypto_kit.updated_client_cipher_suites(cipher_suites);
        crypto_kit.negotiated_cipher_suite()?;
        self.crypto_kit_repository
            .update(connection_id, &crypto_kit)?;
        Ok(())
    }

    fn save_tls_extensions_v1(
        &self,
        extensions: &[Extension],
        connection_id: &[u8],
    ) -> Result<(), SavePacketError> {
        let mut crypto_kit = self.crypto_kit_repository.crypto_kit(connection_id)?;
        let mut transport_parameter = match self
            .transport_parameter_repository
            .transport_parameters(connection_id)
        {
            Err(RepositoryError::NotFound) => TransportParameters::new(),
            Err(e) => return Err(e).map_err(Into::into),
            Ok(tp) => tp,
        };
        let mut app = match self.app_repository.app(connection_id) {
            Err(RepositoryError::NotFound) => AppData::new(),
            Err(e) => return Err(e).map_err(Into::into),
            Ok(a) => a,
        };
        for extension in extensions {
            match extension {
                Extension::ServerName(e) => {
                    crypto_kit.updated_client_server_names(e.server_names());
                }
                Extension::SupportedGroups(e) => {
                    crypto_kit.updated_client_named_curves(e.named_curves());
                }
                Extension::Alpn(e) => {
                    app.updated_client_app_protocols(e.protocol_names());
                }
                Extension::SignatureAlgorithms(e) => {
                    crypto_kit.updated_client_signature_algorithms(e.signature_schemes());
                }
                Extension::KeyShare(e) => match e {
                    key_share::Extension::Server {
                        entry: _,
                        length: _,
                    } => {
                        unreachable!("reading client initial, but found server hello info")
                    }
                    key_share::Extension::Client { entries, length: _ } => {
                        crypto_kit.updated_client_key_shares(entries);
                    }
                },
                Extension::PskKeyExchangeModes(e) => {
                    crypto_kit.updated_client_psk_key_exchange_modes(e.modes());
                }
                Extension::SupportedVersions(e) => match e {
                    supported_versions::Extension::Server(_) => {
                        unreachable!("reading client initial, but found server hello info")
                    }
                    supported_versions::Extension::Client {
                        versions,
                        length: _,
                    } => {
                        crypto_kit.updated_client_supported_versions(versions);
                    }
                },
                Extension::QuicTransportParameters(e) => {
                    transport_parameter.updated_client_transport_parameters(e.parameters());
                }
                _ => { /* do nothing */ }
            }
        }
        // 含まれてないケースも考慮して、ここでネゴシエーションの整合性処理を行う
        crypto_kit.negotiated_server_name()?;
        crypto_kit.negotiated_named_curve()?;
        app.negotiated_app_protocol()?;
        crypto_kit.negotiated_signature_algorithm()?;
        crypto_kit.negotiated_key_shares()?;
        crypto_kit.negotiated_psk_key_exchange_mode()?;
        crypto_kit.negotiated_supported_version()?;
        transport_parameter.negotiated_transport_parameters();
        self.crypto_kit_repository
            .update(connection_id, &crypto_kit)?;
        self.transport_parameter_repository
            .update(connection_id, &transport_parameter)?;
        self.app_repository.update(connection_id, &app)?;
        Ok(())
    }

    fn send_server_hello_v1(
        &self,
        socket_address: &SocketAddr,
        destination_connection_id: &[u8],
    ) -> Result<(), SendError> {
        if !self.is_prepared_server_hello(destination_connection_id)? {
            // 準備ができていないのでまだ送信しない
            return Ok(());
        }
        tracing::debug!("send server hello");
        Ok(())
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
    IsAfterHandshakeDoneError(#[from] JudgeError),
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
    #[error("send error")]
    SendError(#[from] SendError),
}

#[derive(thiserror::Error, Debug)]
pub enum SavePacketError {
    #[error("parse frame error")]
    ParseFrameError(#[from] ParseFrameError),
    #[error("handshake transform error")]
    HandshakeTransformError(#[from] HandshakeTransformError),
    #[error("repository error")]
    RepositoryError(#[from] repository::RepositoryError),
    #[error("crypto kit negotiation error")]
    CryptoKitNegotiationError(#[from] crypto_kit::NegotiationError),
    #[error("app negotiation error")]
    AppNegotiationError(#[from] app::NegotiationError),
}

#[derive(thiserror::Error, Debug)]
pub enum JudgeError {
    #[error("repository error")]
    RepositoryError(#[from] repository::RepositoryError),
}

#[derive(thiserror::Error, Debug)]
pub enum IsAfterHelloError {
    #[error("repository error")]
    RepositoryError(#[from] repository::RepositoryError),
}

#[derive(thiserror::Error, Debug)]
pub enum SendError {
    #[error("judge error")]
    JudgeError(#[from] JudgeError),
    #[error("repository error")]
    RepositoryError(#[from] repository::RepositoryError),
}
