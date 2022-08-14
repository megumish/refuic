use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};
use immic_common::{QuicVersion, ReadVarInt};

use super::{Packet, PacketTransformError};

#[derive(Debug, PartialEq, Clone)]
pub struct LongHeaderPacket {
    fixed_bit: bool,
    long_packet_type: LongPacketType,
    type_specific_bits: [bool; 4],
    version: QuicVersion,
    destination_connection_id: Vec<u8>,
    source_connection_id: Vec<u8>,
    version_specific_data: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum LongPacketType {
    VersionNegotiation,
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

pub fn parse_from_packet(
    packet: Packet,
    version: QuicVersion,
) -> Result<LongHeaderPacket, PacketTransformError> {
    match version {
        QuicVersion::Rfc9000 => parse_from_packet_v1(packet),
        _ => Err(PacketTransformError::NoSupportVersion),
    }
}

pub fn parse_from_packet_v1(packet: Packet) -> Result<LongHeaderPacket, PacketTransformError> {
    let fixed_bit = ((0b0100_0000 & packet.version_specific_bits) >> 6) == 1;

    let mut input = Cursor::new(packet.type_specific_bytes);
    let version = {
        let version = input.read_u32::<NetworkEndian>()?;
        version.into()
    };

    let long_packet_type = {
        if &version == &QuicVersion::VersionNegotiation {
            LongPacketType::VersionNegotiation
        } else {
            let long_packet_type_byte = (0b0011_0000 & packet.version_specific_bits) >> 4;
            match long_packet_type_byte {
                0b00 => LongPacketType::Initial,
                0b01 => LongPacketType::ZeroRtt,
                0b10 => LongPacketType::Handshake,
                0b11 => LongPacketType::Retry,
                _ => unreachable!(),
            }
        }
    };

    let mut type_specific_bits = [false; 4];
    type_specific_bits[0] = ((0b1000 & packet.version_specific_bits) >> 3) == 1;
    type_specific_bits[1] = ((0b0100 & packet.version_specific_bits) >> 2) == 1;
    type_specific_bits[2] = ((0b0010 & packet.version_specific_bits) >> 1) == 1;
    type_specific_bits[3] = (0b0001 & packet.version_specific_bits) == 1;

    let destination_connection_id = {
        let var_int = input.read_var_int()?;
        let length = var_int.u64() as usize;
        let mut buf = vec![0u8; length];
        let _ = input.read_exact(&mut buf);
        buf
    };
    let source_connection_id = {
        let var_int = input.read_var_int()?;
        let length = var_int.u64() as usize;
        let mut buf = vec![0u8; length];
        let _ = input.read_exact(&mut buf);
        buf
    };
    let version_specific_data = {
        let mut buf = Vec::new();
        let _ = input.read_to_end(&mut buf);
        buf
    };
    Ok(LongHeaderPacket {
        fixed_bit,
        long_packet_type,
        type_specific_bits,
        version,
        destination_connection_id,
        source_connection_id,
        version_specific_data,
    })
}
