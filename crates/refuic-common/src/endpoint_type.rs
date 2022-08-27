#[derive(Debug, PartialEq, Clone)]
pub enum EndpointType {
    Server,
    Client,
}

impl EndpointType {
    pub fn reverse(&self) -> Self {
        match self {
            EndpointType::Server => EndpointType::Client,
            EndpointType::Client => EndpointType::Server,
        }
    }
}
