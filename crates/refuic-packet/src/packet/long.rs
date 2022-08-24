use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};
use refuic_common::{var_int::NewVarIntError, QuicVersion, ReadVarInt};
use refuic_crypto::Aes128GcmEncryptError;

use self::remove_protection::RemoveProtectionError;

use super::{Packet, PacketTransformError};

pub mod handshake;
pub mod initial;
pub mod remove_protection;

pub use remove_protection::remove_protection;

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

impl LongHeaderPacket {
    pub fn to_vec(&self) -> Vec<u8> {
        let first_byte = (1 << 7) // long header
            + (if self.fixed_bit { 1} else { 0 } << 6) // fixed bit
            + (self.long_packet_type.u8() << 4) // long packet type
            + type_specific_bits_to_half_byte(self.type_specific_bits);

        let mut ret = Vec::new();
        ret.push(first_byte);
        ret.extend(self.version.to_bytes());
        ret.push(self.destination_connection_id.len() as u8);
        ret.extend(&self.destination_connection_id);
        ret.push(self.source_connection_id.len() as u8);
        ret.extend(&self.source_connection_id);
        ret.extend(&self.version_specific_data);
        ret
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum LongPacketType {
    VersionNegotiation,
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongPacketType {
    fn u8(&self) -> u8 {
        match self {
            Self::Initial | Self::VersionNegotiation => 0b00,
            Self::ZeroRtt => 0b01,
            Self::Handshake => 0b10,
            Self::Retry => 0b11,
        }
    }
}

pub fn parse_from_packet(
    packet: Packet,
    version: &QuicVersion,
) -> Result<LongHeaderPacket, PacketTransformError> {
    match version {
        QuicVersion::Rfc9000 => parse_from_packet_v1(packet),
        _ => Err(PacketTransformError::NoSupportVersion),
    }
}

pub fn parse_from_bytes(
    buf: &[u8],
    version: &QuicVersion,
) -> Result<LongHeaderPacket, PacketTransformError> {
    let packet = super::parse_from_bytes(buf)?;
    parse_from_packet(packet, version)
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

#[derive(thiserror::Error, Debug)]
pub enum LongHeaderPacketTransform {
    #[error("std I/O error")]
    StdIoErro(#[from] std::io::Error),
    #[error("packet transform error")]
    PacketTransformError(#[from] PacketTransformError),
    #[error("remove protection error")]
    RemoveProtectionError(#[from] RemoveProtectionError),
}

#[derive(thiserror::Error, Debug)]
pub enum ProtectError {
    #[error("new var int error")]
    NewVarIntError(#[from] NewVarIntError),
    #[error("aes 128 gcm encrypt error")]
    Aes128GcmEncryptError(#[from] Aes128GcmEncryptError),
}

fn type_specific_bits_to_half_byte(bits: [bool; 4]) -> u8 {
    let mut type_specific_half_byte = 0u8;
    type_specific_half_byte += (bits[0] as u8) << 3;
    type_specific_half_byte += (bits[1] as u8) << 2;
    type_specific_half_byte += (bits[2] as u8) << 1;
    type_specific_half_byte += (bits[3] as u8) << 0;
    type_specific_half_byte
}

fn type_specific_half_byte_to_bits(half_byte: u8) -> [bool; 4] {
    let mut type_speicific_bits = [false; 4];
    type_speicific_bits[0] = (half_byte >> 3) == 1;
    type_speicific_bits[1] = ((half_byte >> 2) & 1) == 1;
    type_speicific_bits[2] = ((half_byte >> 1) & 1) == 1;
    type_speicific_bits[3] = ((half_byte >> 0) & 1) == 1;
    type_speicific_bits
}
