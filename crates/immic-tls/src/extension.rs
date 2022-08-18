use std::io::{Cursor, Read};

pub mod key_share;
pub mod supported_versions;

use byteorder::{NetworkEndian, ReadBytesExt};

#[derive(Debug, PartialEq, Clone)]
pub enum Extension {
    SupportedVersions(supported_versions::Extension),
    KeyShare(key_share::Extension),
    Others {
        extension_type: u16,
        extension_data: Vec<u8>,
    },
}

impl Extension {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::SupportedVersions(e) => [
                &43u16.to_be_bytes(),
                &(e.len() as u16).to_be_bytes(),
                &e.to_vec()[..],
            ]
            .concat(),
            Self::KeyShare(e) => [
                &51u16.to_be_bytes(),
                &(e.len() as u16).to_be_bytes(),
                &e.to_vec()[..],
            ]
            .concat(),
            Self::Others {
                extension_type,
                extension_data,
            } => [
                &extension_type.to_be_bytes(),
                &(extension_data.len() as u16).to_be_bytes(),
                &extension_data[..],
            ]
            .concat(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::SupportedVersions(e) => 2 + 2 + e.len(),
            Self::KeyShare(e) => 2 + 2 + e.len(),
            Self::Others {
                extension_type: _,
                extension_data,
            } => 2 + 2 + extension_data.len(),
        }
    }
}

macro_rules! try_read {
    ($expr:expr, $extensions:ident, $read_length:ident) => {
        match $expr {
            Err(err) => match err.kind() {
                std::io::ErrorKind::UnexpectedEof => return Ok(($extensions, $read_length)),
                _ => return Err(err).map_err(Into::into),
            },
            Ok(x) => x,
        }
    };
}

pub fn read_extensions(
    input: &mut Cursor<&[u8]>,
) -> Result<(Vec<Extension>, usize), ReadExtensionsError> {
    let mut read_length = 0usize;

    let mut extensions = Vec::new();

    let _total_length = try_read!(input.read_u16::<NetworkEndian>(), extensions, read_length);
    read_length += 2;

    loop {
        let mut this_read_length = 0usize;
        let extension_type = try_read!(input.read_u16::<NetworkEndian>(), extensions, read_length);
        this_read_length += 2;

        let extension_data = {
            let length = try_read!(input.read_u16::<NetworkEndian>(), extensions, read_length);
            this_read_length += 2;
            let mut buf = vec![0; length as usize];
            try_read!(input.read_exact(&mut buf), extensions, read_length);
            this_read_length += length as usize;
            buf
        };

        extensions.push(Extension::Others {
            extension_type,
            extension_data,
        });
        read_length += this_read_length;
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ReadExtensionsError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}
