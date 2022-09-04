use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::connection::{ConnectionRepository, ConnectionRfc9000};

#[derive(Default, Debug)]
pub struct Repository {
    inner: Arc<Mutex<HashMap<Vec<u8>, ConnectionRfc9000>>>,
}

impl ConnectionRepository for Repository {
    fn connection_v1(
        &self,
        connection_id: &[u8],
    ) -> Result<crate::connection::ConnectionRfc9000, crate::repository::RepositoryError> {
        let inner =
            self.inner
                .lock()
                .or(Err(crate::repository::RepositoryError::InternalError {
                    description: "Mutex Lock Failed".to_owned(),
                }))?;
        let connection = inner.get(connection_id);
        if let Some(connection) = connection {
            Ok(connection.clone())
        } else {
            Err(crate::repository::RepositoryError::NotFound)
        }
    }
    fn update_v1(
        &self,
        connection_id: &[u8],
        connection: &ConnectionRfc9000,
    ) -> Result<(), crate::repository::RepositoryError> {
        let mut inner =
            self.inner
                .lock()
                .or(Err(crate::repository::RepositoryError::InternalError {
                    description: "Mutex Lock Failed".to_owned(),
                }))?;
        let _ = inner.insert(connection_id.to_owned(), connection.clone());
        Ok(())
    }
}
