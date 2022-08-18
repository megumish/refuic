pub mod client_hello;
pub mod server_hello;

#[derive(thiserror::Error, Debug)]
pub enum HandshakeTransformError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
    #[error("not this type")]
    NotThisHandshakeType,
    #[error("invalid protocol version number")]
    InvalidProtocolVersion,
    #[error("read extensions error")]
    ReadExtensionsError(#[from] crate::extension::ReadExtensionsError),
}
