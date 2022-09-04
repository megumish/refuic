use refuic_tls::extension::quic_transport_parameters::TransportParameter;

use crate::repository::RepositoryError;

pub trait TransportParameterRepository {
    fn update_client_transport_parameters_v1(
        &self,
        connection_id: &[u8],
        parameters: &[TransportParameter],
    ) -> Result<(), RepositoryError>;
}
