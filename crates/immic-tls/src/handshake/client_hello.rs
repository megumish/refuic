use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};

use crate::extension::{read_extensions, Extension};

use super::HandshakeTransformError;

#[derive(Debug, PartialEq, Clone)]
pub struct ClientHelloData {
    pub(crate) length: usize,
    pub(crate) random: [u8; 32],
    pub(crate) legacy_session_id: Vec<u8>,
    pub(crate) cipher_suites: Vec<[u8; 2]>,
    pub(crate) legacy_compression_method: Vec<u8>,
    pub(crate) extensions: Vec<Extension>,
    pub total_length: usize,
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

    let mut actual_remain_length = 0usize;

    {
        let mut buf = [0u8; 2];
        input.read_exact(&mut buf)?;
        actual_remain_length += 2;
        if buf != [0x03, 0x03] {
            return Err(HandshakeTransformError::InvalidProtocolVersion);
        }
    };

    let random = {
        let mut buf = [0u8; 32];
        input.read_exact(&mut buf)?;
        actual_remain_length += 32;
        buf
    };

    let legacy_session_id = {
        let length = input.read_u8()?;
        let mut buf = vec![0; length as usize];
        input.read_exact(&mut buf)?;
        actual_remain_length += 1 + length as usize;
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
        actual_remain_length += 2 + length as usize;
        vec
    };

    let legacy_compression_method = {
        let length = input.read_u8()?;
        let mut buf = vec![0; length as usize];
        input.read_exact(&mut buf)?;
        actual_remain_length += 1 + length as usize;
        buf
    };

    let (extensions, total_length) = {
        let (extensions, read_length) = read_extensions(&mut input)?;
        (extensions, 4 + actual_remain_length + read_length)
    };

    Ok(ClientHelloData {
        length,
        random,
        legacy_session_id,
        cipher_suites,
        legacy_compression_method,
        extensions,
        total_length,
    })
}
