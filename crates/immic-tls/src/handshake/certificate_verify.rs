use crate::signature_scheme::SignatureScheme;

pub struct CertificateVerify {
    length: usize,
    algorithm: SignatureScheme,
    signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn new(signature_scheme: &SignatureScheme, signature: &[u8]) -> Self {
        Self {
            length: signature_scheme.len() + signature.len(),
            algorithm: signature_scheme.clone(),
            signature: signature.to_vec(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let message_type = 15u8;
        let length_bytes = {
            let mut buf = Vec::new();
            for i in 0..3usize {
                buf.push(((self.length >> (3 - (i + 1)) * 8) & 0xff) as u8)
            }
            buf
        };
        [
            &[message_type],
            &length_bytes[..],
            &self.algorithm.to_bytes(),
            &(self.signature.len() as u16).to_be_bytes()[..],
            &self.signature,
        ]
        .concat()
    }
}
