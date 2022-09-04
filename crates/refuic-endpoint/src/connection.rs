use std::net::SocketAddr;

use crate::{
    repository::RepositoryError,
    space::{AppDataSpaceRfc9000, HandshakeSpaceRfc9000, InitialSpaceRfc9000},
};

pub trait ConnectionRepository {
    fn new_connection_v1(
        &self,
        connection_id: &[u8],
        socket: SocketAddr,
    ) -> Result<&ConnectionRfc9000, RepositoryError>;
    fn connection_v1(
        &self,
        connection_id: &[u8],
    ) -> Result<Option<&ConnectionRfc9000>, RepositoryError>;

    fn is_acknowlegded_hello(&self, connection_id: &[u8]) -> Result<bool, RepositoryError>;
}

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
