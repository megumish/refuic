use aes_gcm::{Aes128Gcm, KeySizeUser};
use hmac::digest::OutputSizeUser;
use sha2::Sha256;

use crate::hkdf_expand::hkdf_expand_sha256;

pub fn hkdf_expand_label_sha256_sha256_len(secret: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    let length = Sha256::output_size();
    hkdf_expand_label_sha256(secret, label, context, length)
}

pub fn hkdf_expand_label_sha256_aes_gcm_128_key_len(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
) -> Vec<u8> {
    let length = Aes128Gcm::key_size();
    hkdf_expand_label_sha256(secret, label, context, length)
}

pub fn hkdf_expand_label_sha256_aes_gcm_128_iv_len(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
) -> Vec<u8> {
    let length = 12; // iv size
    hkdf_expand_label_sha256(secret, label, context, length)
}

fn hkdf_expand_label_sha256(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let label = ["tls13 ".as_bytes(), label].concat();
    let hkdf_label = [
        &(length as u16).to_be_bytes()[..],
        &[label.len() as u8],
        &label,
        &[context.len() as u8],
        context,
    ]
    .concat();
    hkdf_expand_sha256(secret, &hkdf_label, length)
}
