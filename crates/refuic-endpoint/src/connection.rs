use crate::{
    repository::RepositoryError,
    space::{AppDataSpaceRfc9000, HandshakeSpaceRfc9000, InitialSpaceRfc9000},
};

pub trait ConnectionRepository {
    fn connection_v1(&self, connection_id: &[u8]) -> Result<ConnectionRfc9000, RepositoryError>;
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConnectionRfc9000 {
    pub(super) initial_space: InitialSpaceRfc9000,
    pub(super) handshake_space: HandshakeSpaceRfc9000,
    pub(super) app_space: AppDataSpaceRfc9000,
}

impl ConnectionRfc9000 {
    pub(crate) fn is_acknowlegded_hello(&self) -> bool {
        todo!()
    }
}
