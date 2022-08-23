use crate::{cipher_suite::CipherSuite, derive_secret, early_secret, hkdf_extract_func};

pub mod certificate;
pub mod certificate_verify;
pub mod client_hello;
pub mod encrypted_extensions;
pub mod finished;
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

pub(crate) fn handshake_secret(
    pre_shared_key: &[u8],
    shared_secret: &[u8],
    cipher_suite: &CipherSuite,
) -> Vec<u8> {
    hkdf_extract_func(cipher_suite)(
        shared_secret,
        &derive_secret(
            &early_secret(pre_shared_key, cipher_suite),
            b"derived",
            b"",
            cipher_suite,
        ),
    )
}

pub(crate) fn server_handshake_traffic_secret(
    pre_shared_key: &[u8],
    shared_secret: &[u8],
    ch_to_sh_message: &[u8],
    cipher_suite: &CipherSuite,
) -> Vec<u8> {
    derive_secret(
        &handshake_secret(pre_shared_key, shared_secret, cipher_suite),
        b"s hs traffic",
        ch_to_sh_message,
        cipher_suite,
    )
}
