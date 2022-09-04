use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::app::{AppData, AppRepository};

#[derive(Default, Debug)]
pub struct Repository {
    inner: Arc<Mutex<HashMap<Vec<u8>, AppData>>>,
}

impl AppRepository for Repository {
    fn app(
        &self,
        connection_id: &[u8],
    ) -> Result<crate::app::AppData, crate::repository::RepositoryError> {
        let inner =
            self.inner
                .lock()
                .or(Err(crate::repository::RepositoryError::InternalError {
                    description: "Mutex Lock Failed".to_owned(),
                }))?;
        let app = inner.get(connection_id);
        if let Some(app) = app {
            Ok(app.clone())
        } else {
            Err(crate::repository::RepositoryError::NotFound)
        }
    }
    fn update(
        &self,
        connection_id: &[u8],
        app: &AppData,
    ) -> Result<(), crate::repository::RepositoryError> {
        let mut inner =
            self.inner
                .lock()
                .or(Err(crate::repository::RepositoryError::InternalError {
                    description: "Mutex Lock Failed".to_owned(),
                }))?;
        let _ = inner.insert(connection_id.to_owned(), app.clone());
        Ok(())
    }
}
