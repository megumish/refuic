use crate::repository::RepositoryError;

pub trait TransportParametersRepository {
    fn transport_parameters(
        &self,
        connection_id: &[u8],
    ) -> Result<crate::transport_parameter::TransportParameters, crate::repository::RepositoryError>;
    fn update(
        &self,
        connection_id: &[u8],
        transport_parameter: &TransportParameters,
    ) -> Result<(), RepositoryError>;
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TransportParameters {
    client_inner: Vec<refuic_common::TransportParameter>,
    inner: Vec<refuic_common::TransportParameter>,
}

impl TransportParameters {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn updated_client_transport_parameters(
        &mut self,
        client_transport_parameter_request: &[refuic_common::TransportParameter],
    ) {
        self.client_inner = client_transport_parameter_request.to_owned()
    }
    pub fn negotiated_transport_parameters(&mut self) {
        // clientからきたパラメーターをそのまま使う
        self.inner = self.client_inner.clone();
        self.client_inner = Vec::new();
    }
    pub fn is_negotiated_transport_parameters(&self) -> bool {
        self.client_inner.is_empty() && !self.inner.is_empty()
    }
}
