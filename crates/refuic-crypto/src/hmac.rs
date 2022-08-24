use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn hmac_sha256(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take a key of any size");
    mac.update(bytes);
    mac.finalize().into_bytes().to_vec()
}
