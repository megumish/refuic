use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};
use ed25519_dalek::Keypair;
use rand::{rngs::StdRng, SeedableRng};
use refuic_common::EndpointType;

use crate::named_curve::NamedCurve;

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub enum Extension {
    Server {
        entry: KeyShareEntry,
        length: usize,
    },
    Client {
        entries: Vec<KeyShareEntry>,
        length: usize,
    },
}

#[derive(Debug, PartialEq, Clone)]
pub struct KeyShareEntry {
    named_group: NamedCurve,
    key: Vec<u8>,
}

impl Extension {
    pub fn new_server_from_entry(key_share_entry: &KeyShareEntry) -> super::Extension {
        super::Extension::KeyShare(Self::Server {
            entry: key_share_entry.clone(),
            length: 2 + key_share_entry.named_group.len() + 2 + key_share_entry.key.len(),
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Server { entry, length } => [
                &(*length as u16).to_be_bytes()[..],
                &entry.named_group.to_bytes(),
                &(entry.key.len() as u16).to_be_bytes(),
                &entry.key[..],
            ]
            .concat(),
            Self::Client {
                entries: es,
                length,
            } => [
                &(*length as u16).to_be_bytes()[..],
                &es.iter()
                    .flat_map(|e| {
                        [
                            &e.named_group.to_bytes(),
                            &(e.key.len() as u16).to_be_bytes(),
                            &e.key[..],
                        ]
                        .concat()
                    })
                    .collect::<Vec<u8>>(),
            ]
            .concat(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Server { entry: _, length } => 2 + length,
            Self::Client { entries: _, length } => 2 + length,
        }
    }
}

impl KeyShareEntry {
    pub fn named_group(&self) -> &NamedCurve {
        &self.named_group
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn new(named_group: &NamedCurve) -> (Self, Vec<u8>) {
        let mut random_generator = StdRng::from_entropy();
        let (key, private_key) = match named_group {
            NamedCurve::Deprecated(_) => todo!(),
            NamedCurve::Reserved(_) => todo!(),
            NamedCurve::Secp256r1 => todo!(),
            NamedCurve::Secp384rl => todo!(),
            NamedCurve::Secp521r1 => todo!(),
            NamedCurve::X25519 => {
                let keypair: Keypair = Keypair::generate(&mut random_generator);
                (
                    keypair.public.as_bytes().to_vec(),
                    keypair.secret.as_bytes().to_vec(),
                )
            }
            NamedCurve::X448 => todo!(),
            NamedCurve::Others(_) => todo!(),
        };
        (
            Self {
                named_group: named_group.clone(),
                key,
            },
            private_key,
        )
    }
}

pub fn parse_from_bytes(
    bytes: &[u8],
    endpoint_type: &EndpointType,
) -> Result<super::Extension, ReadExtensionsError> {
    let mut input = Cursor::new(bytes);
    let length = input.read_u16::<NetworkEndian>()? as usize;
    match endpoint_type {
        EndpointType::Client => {
            let mut sum_of_length = 0;
            let mut entries = Vec::new();
            while sum_of_length < length {
                let named_group = {
                    let ng = input.read_u16::<NetworkEndian>()?;
                    NamedCurve::from_u16(ng)
                };
                sum_of_length += 2;
                let key = {
                    let key_length = input.read_u16::<NetworkEndian>()? as usize;
                    let mut key = vec![0; key_length];
                    input.read_exact(&mut key)?;
                    sum_of_length += 2 + key_length;
                    key
                };
                entries.push(KeyShareEntry { named_group, key })
            }
            Ok(super::Extension::KeyShare(Extension::Client {
                entries,
                length,
            }))
        }
        EndpointType::Server => {
            let named_group = {
                let ng = input.read_u16::<NetworkEndian>()?;
                NamedCurve::from_u16(ng)
            };
            let key = {
                let key_length = input.read_u16::<NetworkEndian>()? as usize;
                let mut key = vec![0; key_length];
                input.read_exact(&mut key)?;
                key
            };
            Ok(super::Extension::KeyShare(Extension::Server {
                entry: KeyShareEntry { named_group, key },
                length,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use refuic_common::EndpointType;

    use crate::{
        extension::{read_extension, Extension},
        named_curve::NamedCurve,
    };

    #[test]
    fn read_extension_key_share() -> Result<(), anyhow::Error> {
        let bytes = include_bytes!("./test_data/xargs_org/client_initial_0/key_share.bin");
        let mut input = Cursor::new(&bytes[..]);
        let extension = read_extension(&mut input, &EndpointType::Client)?;
        assert_eq!(
            extension,
            Extension::KeyShare(super::Extension::Client {
                entries: vec![super::KeyShareEntry {
                    named_group: NamedCurve::X25519,
                    key: vec![
                        0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a,
                        0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75,
                        0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54
                    ],
                }],
                length: 36
            })
        );
        assert_eq!(extension.to_vec(), bytes);
        Ok(())
    }
}
