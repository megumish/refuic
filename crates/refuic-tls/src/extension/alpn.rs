use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    protocol_names: Vec<Vec<u8>>,
    length: usize,
}

impl Extension {
    pub fn len(&self) -> usize {
        2 + self.length
    }

    pub fn protocol_names(&self) -> &Vec<Vec<u8>> {
        &self.protocol_names
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [
            &(self.length as u16).to_be_bytes()[..],
            &self
                .protocol_names
                .iter()
                .flat_map(|pn| [&[pn.len() as u8][..], &pn].concat())
                .collect::<Vec<u8>>(),
        ]
        .concat()
    }
}

pub fn parse_from_bytes(bytes: &[u8]) -> Result<super::Extension, ReadExtensionsError> {
    let mut input = Cursor::new(bytes);
    let (protocol_names, length) = {
        let length = input.read_u16::<NetworkEndian>()? as usize;
        let mut protocol_names = Vec::new();
        let mut sum_of_length = 0;
        while sum_of_length < length {
            let name_length = input.read_u8()? as usize;
            let mut name = vec![0; name_length];
            input.read_exact(&mut name)?;
            sum_of_length += 1 + name_length;
            protocol_names.push(name);
        }
        (protocol_names, length)
    };

    Ok(super::Extension::Alpn(Extension {
        protocol_names,
        length,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use refuic_common::EndpointType;

    use crate::extension::{read_extension, Extension};

    #[test]
    fn read_extension_alpn() -> Result<(), anyhow::Error> {
        let bytes = include_bytes!("./test_data/xargs_org/client_initial_0/alpn.bin");
        let mut input = Cursor::new(&bytes[..]);
        let extension = read_extension(&mut input, &EndpointType::Client)?;
        assert_eq!(
            extension,
            Extension::Alpn(super::Extension {
                protocol_names: vec![b"ping/1.0".to_vec()],
                length: 9
            })
        );
        assert_eq!(extension.to_vec(), bytes);
        Ok(())
    }
}
