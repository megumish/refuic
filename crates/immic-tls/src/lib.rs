use cipher_suite::CipherSuite;
use immic_crypto::{hash::sha256, hkdf_expand_label, hkdf_extract_sha256, hmac::hmac_sha256};

pub mod cipher_suite;
pub mod extension;
pub mod handshake;
pub mod named_group;
pub mod signature_scheme;

pub(crate) fn early_secret(pre_shared_key: &[u8], cipher_suite: &CipherSuite) -> Vec<u8> {
    hkdf_extract_func(cipher_suite)(pre_shared_key, b"")
}

pub(crate) fn derive_secret(
    secret: &[u8],
    label: &[u8],
    messages: &[u8],
    cipher_suite: &CipherSuite,
) -> Vec<u8> {
    match cipher_suite {
        CipherSuite::TlsAes128GcmSha256 => {
            hkdf_expand_label::hkdf_expand_label_sha256_aes_gcm_128_hash_len(
                secret, label, messages,
            )
        }
        _ => unimplemented!(),
    }
}

pub(crate) fn hkdf_extract_func(
    cipher_suite: &CipherSuite,
) -> impl FnOnce(&[u8], &[u8]) -> Vec<u8> {
    match cipher_suite {
        CipherSuite::TlsAes128GcmSha256
        | CipherSuite::TlsChaCha30Poly1305Sha256
        | CipherSuite::TlsAes128Ccm8Sha256 => hkdf_extract_sha256,
        _ => unimplemented!(),
    }
}

pub(crate) fn hmac_func(cipher_suite: &CipherSuite) -> impl FnOnce(&[u8], &[u8]) -> Vec<u8> {
    match cipher_suite {
        CipherSuite::TlsAes128GcmSha256
        | CipherSuite::TlsChaCha30Poly1305Sha256
        | CipherSuite::TlsAes128Ccm8Sha256 => hmac_sha256,
        _ => unimplemented!(),
    }
}

pub(crate) fn transcript_hash_func(
    cipher_suite: &CipherSuite,
) -> impl FnOnce(Vec<Vec<u8>>) -> Vec<u8> {
    match cipher_suite {
        CipherSuite::TlsAes128GcmSha256
        | CipherSuite::TlsChaCha30Poly1305Sha256
        | CipherSuite::TlsAes128Ccm8Sha256 => sha256,
        _ => unimplemented!(),
    }
}
