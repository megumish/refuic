use std::io::Cursor;

use byteorder::{NetworkEndian, ReadBytesExt};
use refuic_common::EndpointType;

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub enum Extension {
    Server(Version),
    Client {
        versions: Vec<Version>,
        length: usize,
    },
}

#[derive(Debug, PartialEq, Clone)]
pub enum Version {
    Tls1_3,
    Others(u16),
}

impl Version {
    fn from_u16(u: u16) -> Self {
        match u {
            0x0304 => Self::Tls1_3,
            x => Self::Others(x),
        }
    }

    fn u16(&self) -> u16 {
        match self {
            Self::Tls1_3 => 0x0304,
            Self::Others(x) => *x,
        }
    }
}

impl Extension {
    pub fn new_server_from_version(version: &Version) -> super::Extension {
        super::Extension::SupportedVersions(Self::Server(version.clone()))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Server(v) => v.u16().to_be_bytes().to_vec(),
            Self::Client { versions, length } => [
                &(*length as u8).to_be_bytes()[..],
                &versions
                    .iter()
                    .map(Version::u16)
                    .map(u16::to_be_bytes)
                    .flatten()
                    .collect::<Vec<u8>>(),
            ]
            .concat(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Server(_) => 1 + 2,
            Self::Client {
                versions: _,
                length,
            } => 1 + length,
        }
    }
}

pub fn parse_from_bytes(
    bytes: &[u8],
    endpoint_type: &EndpointType,
) -> Result<super::Extension, ReadExtensionsError> {
    let mut input = Cursor::new(bytes);
    let length = input.read_u8()? as usize;
    match endpoint_type {
        EndpointType::Client => {
            let mut versions = Vec::new();
            for _ in 0..length / 2 {
                let version = Version::from_u16(input.read_u16::<NetworkEndian>()?);
                versions.push(version)
            }
            Ok(super::Extension::SupportedVersions(Extension::Client {
                versions,
                length,
            }))
        }
        EndpointType::Server => {
            let version = Version::from_u16(input.read_u16::<NetworkEndian>()?);
            Ok(super::Extension::SupportedVersions(Extension::Server(
                version,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use refuic_common::EndpointType;

    use crate::extension::{read_extension, Extension};

    #[test]
    fn read_extension_supported_versions() -> Result<(), anyhow::Error> {
        let bytes = include_bytes!("./test_data/xargs_org/client_initial_0/supported_versions.bin");
        let mut input = Cursor::new(&bytes[..]);
        let extension = read_extension(&mut input, &EndpointType::Client)?;
        assert_eq!(
            extension,
            Extension::SupportedVersions(super::Extension::Client {
                versions: vec![super::Version::Tls1_3],
                length: 2
            })
        );
        assert_eq!(extension.to_vec(), bytes);
        Ok(())
    }
}
