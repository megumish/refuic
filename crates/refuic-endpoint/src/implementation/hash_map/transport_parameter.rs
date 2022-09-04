use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::transport_parameter::{TransportParameters, TransportParametersRepository};

#[derive(Default, Debug)]
pub struct Repository {
    inner: Arc<Mutex<HashMap<Vec<u8>, TransportParameters>>>,
}

impl TransportParametersRepository for Repository {
    fn transport_parameters(
        &self,
        connection_id: &[u8],
    ) -> Result<crate::transport_parameter::TransportParameters, crate::repository::RepositoryError>
    {
        let inner =
            self.inner
                .lock()
                .or(Err(crate::repository::RepositoryError::InternalError {
                    description: "Mutex Lock Failed".to_owned(),
                }))?;
        let transport_parameter = inner.get(connection_id);
        if let Some(transport_parameter) = transport_parameter {
            Ok(transport_parameter.clone())
        } else {
            Err(crate::repository::RepositoryError::NotFound)
        }
    }
    fn update(
        &self,
        connection_id: &[u8],
        transport_parameter: &crate::transport_parameter::TransportParameters,
    ) -> Result<(), crate::repository::RepositoryError> {
        let mut inner =
            self.inner
                .lock()
                .or(Err(crate::repository::RepositoryError::InternalError {
                    description: "Mutex Lock Failed".to_owned(),
                }))?;
        let _ = inner.insert(connection_id.to_owned(), transport_parameter.clone());
        Ok(())
    }
}
