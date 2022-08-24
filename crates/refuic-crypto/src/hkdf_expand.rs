use hmac::{digest::OutputSizeUser, Hmac, Mac};
use sha2::Sha256;

pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let length_of_okm = div_ceil(length, sha2::Sha256::output_size());
    let mut okm = Vec::new();
    let mut t_result = Vec::new();
    for i in 1..length_of_okm + 1 {
        let mut t = Hmac::<Sha256>::new_from_slice(prk).expect("HMAC can take a key of any size");
        t.update(&t_result);
        t.update(info);
        t.update(&[i as u8]);
        t_result = t.finalize().into_bytes().to_vec();
        okm.append(&mut t_result.clone());
    }
    okm[..length].to_vec()
}

fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}
