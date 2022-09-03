use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    server_names: Vec<ServerName>,
    length: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ServerName {
    name_type: NameType,
    host_name: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum NameType {
    HostName,
    Others(u8),
}

impl Extension {
    pub fn len(&self) -> usize {
        2 // length of self.length
         + self.length
    }

    pub fn server_names(&self) -> &Vec<ServerName> {
        &self.server_names
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [
            &(self.length as u16).to_be_bytes()[..],
            &self
                .server_names
                .iter()
                .flat_map(|n| {
                    let name_type = match n.name_type {
                        NameType::HostName => 0,
                        NameType::Others(x) => x,
                    };
                    [
                        &[name_type][..],
                        &(n.host_name.len() as u16).to_be_bytes()[..],
                        &n.host_name,
                    ]
                    .concat()
                })
                .collect::<Vec<u8>>(),
        ]
        .concat()
    }
}

pub fn parse_from_bytes(bytes: &[u8]) -> Result<super::Extension, ReadExtensionsError> {
    let mut input = Cursor::new(bytes);
    let (server_names, length) = {
        let length = input.read_u16::<NetworkEndian>()? as usize;
        let mut names = Vec::new();
        let mut sum_of_length = 0;
        while sum_of_length < length {
            let name_type = input.read_u8()?;
            let name_length = match name_type {
                0 => {
                    let length = input.read_u16::<NetworkEndian>()? as usize;
                    let mut buf = vec![0; length];
                    input.read_exact(&mut buf)?;
                    names.push(ServerName {
                        name_type: NameType::HostName,
                        host_name: buf,
                    });
                    length
                }
                _ => 0,
            };
            sum_of_length += 1 + 2 + name_length;
        }
        (names, length)
    };
    Ok(super::Extension::ServerName(Extension {
        server_names,
        length,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use refuic_common::EndpointType;

    use crate::extension::{read_extension, Extension};

    #[test]
    fn read_extension_server_name() -> Result<(), anyhow::Error> {
        let bytes = include_bytes!("./test_data/xargs_org/client_initial_0/server_name.bin");
        let mut input = Cursor::new(&bytes[..]);
        let extension = read_extension(&mut input, &EndpointType::Client)?;
        assert_eq!(
            extension,
            Extension::ServerName(super::Extension {
                server_names: vec![super::ServerName {
                    name_type: super::NameType::HostName,
                    host_name: b"example.ulfheim.net".to_vec()
                }],
                length: 0x16
            })
        );
        assert_eq!(extension.to_vec(), bytes);
        Ok(())
    }
}
