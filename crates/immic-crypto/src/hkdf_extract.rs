use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC can take a key of any size");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}
