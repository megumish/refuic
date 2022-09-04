use crate::repository::RepositoryError;

pub trait AppRepository {
    fn app(
        &self,
        connection_id: &[u8],
    ) -> Result<crate::app::AppData, crate::repository::RepositoryError>;
    fn update(&self, connection_id: &[u8], app: &AppData) -> Result<(), RepositoryError>;
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AppData {
    client_app_protocols: Vec<Vec<u8>>,
    app_protocol: Option<Vec<u8>>,
}

impl AppData {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn updated_client_app_protocols(&mut self, client_app_protocols: &[Vec<u8>]) {
        self.client_app_protocols = client_app_protocols.to_owned();
    }
    pub fn negotiated_app_protocol(&mut self) -> Result<(), NegotiationError> {
        for client_app_protocol in &self.client_app_protocols {
            for server_app_protocol in server_app_protocols() {
                if client_app_protocol == &server_app_protocol {
                    self.app_protocol = Some(server_app_protocol);
                    self.client_app_protocols = Vec::new();
                    return Ok(());
                }
            }
        }
        Err(NegotiationError::NoSupportAppProtocol)
    }
    pub fn is_negotiated_app_protocol(&self) -> bool {
        self.client_app_protocols.is_empty() && self.app_protocol.is_some()
    }
}

// もっと置くに適切な場所があるかもしれない
fn server_app_protocols() -> [Vec<u8>; 2] {
    [b"ping/1.0".to_vec(), b"h3".to_vec()]
}

#[derive(thiserror::Error, Debug)]
pub enum NegotiationError {
    #[error("No support app protocol")]
    NoSupportAppProtocol,
}
