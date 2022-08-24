use crate::{cipher_suite::CipherSuite, derive_secret, hmac_func, transcript_hash_func};

use super::{
    certificate::Certificate, certificate_verify::CertificateVerify,
    server_handshake_traffic_secret,
};

pub struct Finished {
    length: usize,
    verify_data: Vec<u8>,
}

impl Finished {
    pub fn new_server(
        pre_shared_key: &[u8],
        shared_secret: &[u8],
        ch_to_sh_message: &[u8],
        certificate: &Certificate,
        certificate_verify: &CertificateVerify,
        cipher_suite: &CipherSuite,
    ) -> Self {
        let verify_data = hmac_func(cipher_suite)(
            &derive_secret(
                &server_handshake_traffic_secret(
                    pre_shared_key,
                    shared_secret,
                    ch_to_sh_message,
                    cipher_suite,
                ),
                b"finished",
                b"",
                cipher_suite,
            ),
            &transcript_hash_func(cipher_suite)(vec![
                ch_to_sh_message.to_owned(),
                certificate.to_vec(),
                certificate_verify.to_vec(),
            ]),
        );
        Self {
            length: verify_data.len(),
            verify_data,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        let message_type = 20u8;
        let length_bytes = {
            let mut buf = Vec::new();
            for i in 0..3usize {
                buf.push(((self.length >> (3 - (i + 1)) * 8) & 0xff) as u8)
            }
            buf
        };
        vec.push(message_type);
        vec.extend(length_bytes);
        vec.extend(&self.verify_data);
        vec
    }
}
