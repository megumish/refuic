use std::io::{Cursor, Read};

use immic_common::{QuicVersion, ReadVarInt};

use crate::LongHeaderPacket;

use super::LongHeaderPacketTransform;

#[derive(Debug, PartialEq, Clone)]
pub enum InitialPacket {
    Rfc9000(InitialPacketRfc9000),
}

impl InitialPacket {
    pub fn payload<'a>(&'a self) -> &'a Vec<u8> {
        match self {
            Self::Rfc9000(p) => p.payload(),
        }
    }
}

pub fn parse_from_long(
    long: &LongHeaderPacket,
    version: &QuicVersion,
) -> Result<InitialPacket, LongHeaderPacketTransform> {
    match version {
        QuicVersion::Rfc9000 => parse_from_long_v1(long),
        _ => unimplemented!(),
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct InitialPacketRfc9000 {
    reserved_bits: [bool; 2],
    version: QuicVersion,
    destination_connection_id: Vec<u8>,
    source_connection_id: Vec<u8>,
    token: Vec<u8>,
    packet_number: u32,
    payload: Vec<u8>,
}

impl InitialPacketRfc9000 {
    fn payload<'a>(&'a self) -> &'a Vec<u8> {
        &self.payload
    }
}

pub fn parse_from_long_v1(
    long: &LongHeaderPacket,
) -> Result<InitialPacket, LongHeaderPacketTransform> {
    let reserved_bits = [long.type_specific_bits[0], long.type_specific_bits[1]];

    let version = long.version.clone();
    let destination_connection_id = long.destination_connection_id.clone();
    let source_connection_id = long.source_connection_id.clone();

    let (token, packet_number, payload) = {
        let mut input = Cursor::new(&long.version_specific_data);
        let token_length = input.read_var_int()?;
        let mut token = vec![0; token_length.u64() as usize];
        input.read_exact(&mut token)?;

        let _remain_length = input.read_var_int()?;

        let packet_number_length = ((if long.type_specific_bits[2] { 1 } else { 0 } << 1)
            | (if long.type_specific_bits[3] { 1 } else { 0 }))
            + 1;
        let packet_number = {
            let mut buf = vec![0; packet_number_length];
            input.read_exact(&mut buf)?;
            let mut number = 0u32;
            for b in buf {
                number += (number << 1) + b as u32;
            }
            number
        };

        let mut payload = Vec::new();
        input.read_to_end(&mut payload)?;
        (token, packet_number, payload)
    };

    Ok(InitialPacket::Rfc9000(InitialPacketRfc9000 {
        reserved_bits,
        version,
        destination_connection_id,
        source_connection_id,
        token,
        packet_number,
        payload,
    }))
}
