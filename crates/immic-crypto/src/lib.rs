mod hkdf_expand;
pub mod hkdf_expand_label;
pub mod hkdf_extract;

use aes_gcm::{
    aead::{self, generic_array::GenericArray, Aead},
    aes::{cipher::BlockEncrypt, Aes128},
    Aes128Gcm, KeyInit, KeySizeUser,
};

pub use hkdf_expand_label::hkdf_expand_label_sha256_sha256_len;
pub use hkdf_extract::hkdf_extract_sha256;

pub fn aes_128_gcm_key_len() -> usize {
    Aes128Gcm::key_size()
}

pub fn aes_128_encrypt(key: &[u8], plain_bytes: &[u8]) -> Vec<u8> {
    let mut mask = GenericArray::clone_from_slice(plain_bytes);
    Aes128::new(&GenericArray::from_slice(key)).encrypt_block(&mut mask);
    mask.to_vec()
}

pub fn aes_128_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Aes128GcmDecryptError> {
    let aead_payload = aead::Payload { msg, aad };
    let aes = Aes128Gcm::new(&GenericArray::clone_from_slice(key));

    Ok(aes
        .decrypt(&GenericArray::from_slice(&nonce), aead_payload)
        .map_err(|_| Aes128GcmDecryptError)?)
}

pub fn aes_128_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Aes128GcmEncryptError> {
    let aead_payload = aead::Payload { msg, aad };
    let aes = Aes128Gcm::new(&GenericArray::clone_from_slice(key));

    Ok(aes
        .encrypt(&GenericArray::from_slice(&nonce), aead_payload)
        .map_err(|_| Aes128GcmEncryptError)?)
}

pub fn aes_128_gcm_encrypted_len(length: usize) -> usize {
    let key_length = aes_128_gcm_key_len();
    length + (key_length - length % key_length)
}

#[derive(thiserror::Error, Debug)]
#[error("Crypto Error. Details are not displayed to prevent attacks using error information.")]
pub struct Aes128GcmDecryptError;

#[derive(thiserror::Error, Debug)]
#[error("Crypto Error. Details are not displayed to prevent attacks using error information.")]
pub struct Aes128GcmEncryptError;
