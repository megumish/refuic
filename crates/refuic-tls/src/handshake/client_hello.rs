use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};

use crate::{
    cipher_suite::CipherSuite,
    extension::{read_extensions, Extension},
};

use super::HandshakeTransformError;

#[derive(Debug, PartialEq, Clone)]
pub struct ClientHelloData {
    pub(crate) length: usize,
    pub(crate) random: [u8; 32],
    pub(crate) legacy_session_id: Vec<u8>,
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) legacy_compression_method: Vec<u8>,
    pub(crate) extensions: Vec<Extension>,
}

impl ClientHelloData {
    pub fn to_vec(&self) -> Vec<u8> {
        let message_type = 1u8;
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
            .flat_map(Extension::to_vec)
            .collect::<Vec<u8>>();
        let cipher_suites_bytes = self
            .cipher_suites
            .iter()
            .flat_map(CipherSuite::to_vec)
            .collect::<Vec<u8>>();
        [
            &[message_type],
            &length_bytes[..],
            &legacy_version,
            &self.random,
            &(self.legacy_session_id.len() as u8).to_be_bytes(),
            &self.legacy_session_id,
            &(cipher_suites_bytes.len() as u16).to_be_bytes(),
            &cipher_suites_bytes[..],
            &(self.legacy_compression_method.len() as u8).to_be_bytes(),
            &self.legacy_compression_method[..],
            &(extensions_bytes.len() as u16).to_be_bytes(),
            &extensions_bytes[..],
        ]
        .concat()
    }

    pub fn cipher_suites(&self) -> &Vec<CipherSuite> {
        &self.cipher_suites
    }

    pub fn extensions(&self) -> &Vec<Extension> {
        &self.extensions
    }
}

pub fn parse_from_bytes(bytes: &[u8]) -> Result<ClientHelloData, HandshakeTransformError> {
    let mut input = Cursor::new(bytes);
    let handshake_type = input.read_u8()?;
    if handshake_type != 1 {
        return Err(HandshakeTransformError::NotThisHandshakeType);
    }

    let length = {
        let mut buf = [0u8; 3];
        input.read_exact(&mut buf)?;
        let mut length = 0usize;
        for b in buf {
            length += (length << 8) + b as usize;
        }
        length
    };

    {
        let mut buf = [0u8; 2];
        input.read_exact(&mut buf)?;
        if buf != [0x03, 0x03] {
            return Err(HandshakeTransformError::InvalidProtocolVersion);
        }
    };

    let random = {
        let mut buf = [0u8; 32];
        input.read_exact(&mut buf)?;
        buf
    };

    let legacy_session_id = {
        let length = input.read_u8()?;
        let mut buf = vec![0; length as usize];
        input.read_exact(&mut buf)?;
        buf
    };

    let cipher_suites = {
        let length = input.read_u16::<NetworkEndian>()?;
        let mut vec = Vec::new();
        for _ in 0..length / 2 {
            let mut buf = [0u8; 2];
            input.read_exact(&mut buf)?;
            vec.push(buf);
        }
        vec.iter().map(|x| CipherSuite::from_bytes(x)).collect()
    };

    let legacy_compression_method = {
        let length = input.read_u8()?;
        let mut buf = vec![0; length as usize];
        input.read_exact(&mut buf)?;
        buf
    };

    let extensions = read_extensions(&mut input)?;

    Ok(ClientHelloData {
        length,
        random,
        legacy_session_id,
        cipher_suites,
        legacy_compression_method,
        extensions,
    })
}
