use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::extension::{key_share, supported_versions, Extension};

use super::client_hello::ClientHelloData;

pub struct ServerHelloData {
    length: usize,
    random: [u8; 32],
    legacy_session_id_echo: Vec<u8>,
    cipher_suite: [u8; 2],
    legacy_compression_method: u8,
    extensions: Vec<Extension>,
}

impl ServerHelloData {
    pub fn new(client_hello_data: &ClientHelloData, key: &[u8]) -> Self {
        let random = {
            let mut random_generator = StdRng::from_entropy();
            let mut buf = [0; 32];
            random_generator.fill_bytes(&mut buf);
            buf
        };

        let cipher_suite = select_cipher_suite(&client_hello_data.cipher_suites);

        let length = 2 // length of legacy version
          + 32 // length of random
          + 1 // length of length of legacy session id echo
          + client_hello_data.legacy_session_id.len()
          + 2 // length of cipher suite
          + 1 // length of legacy compression method
          + 2 // length of extensions
          ;

        let mut this = Self {
            length,
            random,
            legacy_session_id_echo: client_hello_data.legacy_session_id.to_owned(),
            cipher_suite,
            legacy_compression_method: 0,
            extensions: Vec::new(),
        };

        // add default extensions
        this.add_extension(supported_versions::Extension::new_only_tls13_server());
        this.add_extension(key_share::Extension::new_x25519_server(key));

        this
    }

    fn add_extension(&mut self, extension: Extension) {
        self.length += extension.len();
        self.extensions.push(extension);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        let message_type = 2u8;
        let length_bytes = {
            let mut buf = Vec::new();
            for i in 0..3usize {
                buf.push(((self.length >> (3 - (i + 1)) * 8) & 0xff) as u8)
            }
            buf
        };
        let legacy_version = [0x03, 0x03];
        let extensions_bytes = self
            .extensions
            .iter()
            .map(Extension::to_vec)
            .flatten()
            .collect::<Vec<u8>>();
        vec.push(message_type);
        vec.extend(length_bytes);
        vec.extend(legacy_version);
        vec.extend(&self.random);
        vec.extend((self.legacy_session_id_echo.len() as u8).to_be_bytes());
        vec.extend(&self.legacy_session_id_echo);
        vec.extend(&self.cipher_suite);
        vec.push(self.legacy_compression_method);
        vec.extend((extensions_bytes.len() as u16).to_be_bytes());
        vec.extend(extensions_bytes);
        vec
    }
}

fn select_cipher_suite(cipher_suites: &Vec<[u8; 2]>) -> [u8; 2] {
    cipher_suites
        .get(0)
        .expect("cipher suites is empty!")
        .clone()
}
