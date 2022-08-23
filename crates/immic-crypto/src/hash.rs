use sha2::{Digest, Sha256};

pub fn sha256(vec_of_bytes: Vec<Vec<u8>>) -> Vec<u8> {
    let mut hasher = Sha256::new();

    for bytes in vec_of_bytes {
        hasher.update(bytes);
    }

    hasher.finalize().to_vec()
}
