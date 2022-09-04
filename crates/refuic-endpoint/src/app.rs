use crate::repository::RepositoryError;

pub trait AppRepository {
    fn update_client_app_protocols_v1(
        &self,
        connection_id: &[u8],
        app_protocols: &[Vec<u8>],
    ) -> Result<(), RepositoryError>;
}
