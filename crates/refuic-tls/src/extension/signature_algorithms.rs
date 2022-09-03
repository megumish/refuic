use std::io::Cursor;

use byteorder::{NetworkEndian, ReadBytesExt};

use crate::signature_scheme::SignatureScheme;

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    signature_schemes: Vec<SignatureScheme>,
    length: usize,
}

impl Extension {
    pub fn len(&self) -> usize {
        2 + self.length
    }

    pub fn signature_schemes(&self) -> &Vec<SignatureScheme> {
        &self.signature_schemes
    }
}

pub fn parse_from_bytes(bytes: &[u8]) -> Result<super::Extension, ReadExtensionsError> {
    let mut input = Cursor::new(bytes);
    let (signature_schemes, length) = {
        let length = input.read_u16::<NetworkEndian>()? as usize;
        let mut schemes = Vec::new();
        for _ in 0..length / 2 {
            let scheme_type = input.read_u16::<NetworkEndian>()?;
            schemes.push(SignatureScheme::from_u16(scheme_type));
        }
        (schemes, length)
    };
    Ok(super::Extension::SignatureAlgorithms(Extension {
        signature_schemes,
        length,
    }))
}
