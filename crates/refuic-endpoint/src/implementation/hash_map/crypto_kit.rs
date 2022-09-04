use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::crypto_kit::{CryptoKit, CryptoKitRepository};

#[derive(Default, Debug)]
pub struct Repository {
    inner: Arc<Mutex<HashMap<Vec<u8>, CryptoKit>>>,
}

impl CryptoKitRepository for Repository {
    fn update(
        &self,
        connection_id: &[u8],
        crypto_kit: &crate::crypto_kit::CryptoKit,
    ) -> Result<(), crate::repository::RepositoryError> {
        let mut inner =
            self.inner
                .lock()
                .or(Err(crate::repository::RepositoryError::InternalError {
                    description: "Mutex Lock Failed".to_owned(),
                }))?;
        let _ = inner.insert(connection_id.to_owned(), crypto_kit.clone());
        Ok(())
    }

    fn crypto_kit(
        &self,
        connection_id: &[u8],
    ) -> Result<crate::crypto_kit::CryptoKit, crate::repository::RepositoryError> {
        let inner =
            self.inner
                .lock()
                .or(Err(crate::repository::RepositoryError::InternalError {
                    description: "Mutex Lock Failed".to_owned(),
                }))?;
        let crypto_kit = inner.get(connection_id);
        if let Some(crypto_kit) = crypto_kit {
            Ok(crypto_kit.clone())
        } else {
            Err(crate::repository::RepositoryError::NotFound)
        }
    }
}
