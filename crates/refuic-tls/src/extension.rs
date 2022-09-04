use std::io::{Cursor, Read};

pub mod alpn;
pub mod key_share;
pub mod psk_key_exchange_modes;
pub mod quic_transport_parameters;
pub mod server_name;
pub mod signature_algorithms;
pub mod supported_groups;
pub mod supported_versions;

use byteorder::{NetworkEndian, ReadBytesExt};
use refuic_common::EndpointType;

#[derive(Debug, PartialEq, Clone)]
pub enum Extension {
    ServerName(server_name::Extension),
    SupportedGroups(supported_groups::Extension),
    SignatureAlgorithms(signature_algorithms::Extension),
    Alpn(alpn::Extension),
    SupportedVersions(supported_versions::Extension),
    PskKeyExchangeModes(psk_key_exchange_modes::Extension),
    KeyShare(key_share::Extension),
    QuicTransportParameters(quic_transport_parameters::Extension),
    Others {
        extension_type: u16,
        extension_data: Vec<u8>,
    },
}

impl Extension {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::ServerName(e) => [
                &0u16.to_be_bytes(),
                &(e.len() as u16).to_be_bytes(),
                &e.to_vec()[..],
            ]
            .concat(),
            Self::SupportedGroups(e) => [
                &10u16.to_be_bytes(),
                &(e.len() as u16).to_be_bytes(),
                &e.to_vec()[..],
            ]
            .concat(),
            Self::SignatureAlgorithms(e) => [
                &13u16.to_be_bytes(),
                &(e.len() as u16).to_be_bytes(),
                &e.to_vec()[..],
            ]
            .concat(),
            Self::Alpn(e) => [
                &16u16.to_be_bytes(),
                &(e.len() as u16).to_be_bytes(),
                &e.to_vec()[..],
            ]
            .concat(),
            Self::SupportedVersions(e) => [
                &43u16.to_be_bytes(),
                &(e.len() as u16).to_be_bytes(),
                &e.to_vec()[..],
            ]
            .concat(),
            Self::PskKeyExchangeModes(e) => [
                &45u16.to_be_bytes(),
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
            Self::QuicTransportParameters(e) => [&57u16.to_be_bytes(), &e.to_vec()[..]].concat(),
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
        2 + 2
            + match self {
                Self::ServerName(e) => e.len(),
                Self::SupportedGroups(e) => e.len(),
                Self::SignatureAlgorithms(e) => e.len(),
                Self::Alpn(e) => e.len(),
                Self::SupportedVersions(e) => e.len(),
                Self::PskKeyExchangeModes(e) => e.len(),
                Self::KeyShare(e) => e.len(),
                Self::QuicTransportParameters(e) => e.len(),
                Self::Others {
                    extension_type: _,
                    extension_data,
                } => extension_data.len(),
            }
    }
}

pub fn read_extensions(
    input: &mut Cursor<&[u8]>,
    target_endpoint_type: &EndpointType,
) -> Result<Vec<Extension>, ReadExtensionsError> {
    let mut extensions = Vec::new();

    let length = input.read_u16::<NetworkEndian>()? as usize;
    let mut sum_of_length = 0;

    while sum_of_length < length {
        let extension = read_extension(input, target_endpoint_type)?;
        sum_of_length += extension.len();
        extensions.push(extension);
    }
    Ok(extensions)
}

fn read_extension(
    input: &mut Cursor<&[u8]>,
    target_endpoint_type: &EndpointType,
) -> Result<Extension, ReadExtensionsError> {
    let extension_type = input.read_u16::<NetworkEndian>()?;

    let extension_data = {
        let length = input.read_u16::<NetworkEndian>()?;
        let mut buf = vec![0; length as usize];
        input.read_exact(&mut buf)?;
        buf
    };
    let extension = match extension_type {
        0 => server_name::parse_from_bytes(&extension_data)?,
        10 => supported_groups::parse_from_bytes(&extension_data)?,
        13 => signature_algorithms::parse_from_bytes(&extension_data)?,
        16 => alpn::parse_from_bytes(&extension_data)?,
        43 => supported_versions::parse_from_bytes(&extension_data, target_endpoint_type)?,
        45 => psk_key_exchange_modes::parse_from_bytes(&extension_data)?,
        51 => key_share::parse_from_bytes(&extension_data, target_endpoint_type)?,
        57 => quic_transport_parameters::parse_from_bytes(&extension_data)?,
        _ => Extension::Others {
            extension_type,
            extension_data,
        },
    };
    Ok(extension)
}

#[derive(thiserror::Error, Debug)]
pub enum ReadExtensionsError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}
