use std::io::{Cursor, Read};

use byteorder::ReadBytesExt;

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

    let header_form = if ((first_byte & 0b1000_0000) >> 7) == 1 {
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
    #[error("this is not long")]
    NotLongPacket,
}
