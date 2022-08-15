use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};

#[derive(Debug, PartialEq, Clone)]
pub enum Extension {
    Others {
        extension_type: u16,
        extension_data: Vec<u8>,
    },
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
