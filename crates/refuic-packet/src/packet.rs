use std::io::{Cursor, Read};

use byteorder::ReadBytesExt;
use refuic_crypto::{
    hkdf_expand_label::{
        hkdf_expand_label_sha256_aes_gcm_128_iv_len, hkdf_expand_label_sha256_aes_gcm_128_key_len,
    },
    hkdf_expand_label_sha256_sha256_len, hkdf_extract_sha256,
};

pub mod long;

#[derive(Debug, PartialEq, Clone)]
pub struct Packet {
    header_form: HeaderForm,
    version_specific_bits: u8,
    type_specific_bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum HeaderForm {
    Long,
    Short,
}

pub fn parse_from_bytes(buf: &[u8]) -> Result<Packet, PacketReadError> {
    let mut input = Cursor::new(buf);

    let first_byte = input.read_u8()?;

    let header_form = if (first_byte & 0b1000_0000) == 1 {
        HeaderForm::Long
    } else {
        HeaderForm::Short
    };

    let version_specific_bits = first_byte & 0b0111_1111;

    let mut type_specific_bytes = Vec::new();
    let _ = input.read_to_end(&mut type_specific_bytes);

    Ok(Packet {
        header_form,
        version_specific_bits,
        type_specific_bytes,
    })
}

#[derive(thiserror::Error, Debug)]
pub enum PacketReadError {
    #[error("std I/O")]
    StdIo(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum PacketTransformError {
    #[error("no support version")]
    NoSupportVersion,
    #[error("std I/O")]
    StdIo(#[from] std::io::Error),
    #[error("packet read error")]
    PacketReadError(#[from] PacketReadError),
}

fn get_key_iv_hp_v1(
    label: &[u8],
    client_destination_connection_id: &[u8],
    initial_salt: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let initial_secret = hkdf_extract_sha256(&initial_salt, client_destination_connection_id);

    let endpoint_initial_secret = hkdf_expand_label_sha256_sha256_len(&initial_secret, label, &[]);

    let key = hkdf_expand_label_sha256_aes_gcm_128_key_len(
        &endpoint_initial_secret,
        "quic key".as_bytes(),
        &[],
    );

    let iv = hkdf_expand_label_sha256_aes_gcm_128_iv_len(
        &endpoint_initial_secret,
        "quic iv".as_bytes(),
        &[],
    );

    let hp = hkdf_expand_label_sha256_aes_gcm_128_key_len(
        &endpoint_initial_secret,
        "quic hp".as_bytes(),
        &[],
    );

    (key, iv, hp)
}
