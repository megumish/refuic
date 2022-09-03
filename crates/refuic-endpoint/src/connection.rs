use std::net::SocketAddr;

use refuic_tls::{cipher_suite::CipherSuite, named_curve::NamedCurve};

use crate::space::{AppDataSpaceRfc9000, HandshakeSpaceRfc9000, InitialSpaceRfc9000};

// trait のエラーハンドリング周りどうすればいいか分からないが、とりあえず他と同じようにenumで定義することにした。
pub trait ConnectionMap {
    fn new_connection_v1(
        &self,
        destination_connection_id: &[u8],
        socket: SocketAddr,
    ) -> Result<&ConnectionRfc9000, NewConnectionError>;
    fn connection_v1(
        &self,
        destination_connection_id: &[u8],
    ) -> Result<Option<&ConnectionRfc9000>, FetchConnectionError>;
    fn update_cipher_suites_v1(
        &self,
        destination_connection_id: &[u8],
        cipher_suites: &[CipherSuite],
    ) -> Result<(), UpdateConnectionError>;
    fn insert_client_named_curves_v1(
        &self,
        destination_connection_id: &[u8],
        named_curves: &[NamedCurve],
    ) -> Result<(), UpdateConnectionError>;
}

#[derive(thiserror::Error, Debug)]
pub enum NewConnectionError {}
#[derive(thiserror::Error, Debug)]
pub enum FetchConnectionError {}
#[derive(thiserror::Error, Debug)]
pub enum UpdateConnectionError {}

#[derive(Debug, PartialEq, Clone)]
pub struct ConnectionRfc9000 {
    pub(super) initial_space: InitialSpaceRfc9000,
    pub(super) handshake_space: HandshakeSpaceRfc9000,
    pub(super) app_space: AppDataSpaceRfc9000,
}

impl ConnectionRfc9000 {
    pub fn initial_space(&self) -> &InitialSpaceRfc9000 {
        &self.initial_space
    }
    pub fn handshake_space(&self) -> &HandshakeSpaceRfc9000 {
        &self.handshake_space
    }
    pub fn is_after_handshake_done(&self) -> bool {
        false
    }
    pub fn is_after_hello(&self) -> bool {
        false
    }
    pub fn initial_destination_connection_id(&self) -> Option<&Vec<u8>> {
        None
    }
}
