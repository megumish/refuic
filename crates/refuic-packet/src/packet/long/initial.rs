use refuic_common::{var_int::VarInt, EndpointType, QuicVersion, ReadVarInt};
use std::io::{Cursor, Read};

mod crypto;
mod endpoint_client;
mod endpoint_server;
mod header_protection;
mod keys;

pub use endpoint_client::{ClientInitialPacket, NewHelloError as ClientNewHelloError};
pub use endpoint_server::{NewHelloError as ServerNewHelloError, ServerInitialPacket};

use crate::packet_number::PacketNumber;

use self::{
    crypto::{decrypt, encrypt, encrypted_len, DecryptError},
    header_protection::{ProtectPacketNumberRfc9000, ProtectTypeSpecificHalfByteRfc9000},
    keys::initial_secret,
};

use super::{type_specific_bits_to_half_byte, LongHeaderPacket, LongPacketType};

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

    pub fn protect(
        &self,
        initial_destination_connection_id: &[u8],
        endpoint_type: &EndpointType,
    ) -> Result<LongHeaderPacket, ProtectError> {
        match self {
            Self::Rfc9000(p) => p.protect(initial_destination_connection_id, endpoint_type),
        }
    }
}

/// この構造体はRFC9000の要件を満たしていることを仮定して扱ってよい
#[derive(Debug, PartialEq, Clone)]
pub struct InitialPacketRfc9000 {
    reserved_bits: [bool; 2],
    destination_connection_id: Vec<u8>,
    source_connection_id: Vec<u8>,
    // tokenの長さはVarIntの取れる値の範囲になる
    token: Vec<u8>,
    packet_number: u32,
    payload: Vec<u8>,
}

impl InitialPacketRfc9000 {
    fn payload<'a>(&'a self) -> &'a Vec<u8> {
        &self.payload
    }

    fn destination_connection_id<'a>(&'a self) -> &'a Vec<u8> {
        &self.destination_connection_id
    }

    fn source_connection_id<'a>(&'a self) -> &'a Vec<u8> {
        &self.source_connection_id
    }

    fn type_specific_half_byte(&self) -> u8 {
        let packet_number = PacketNumber::from_u32(self.packet_number);
        (u8::from(self.reserved_bits[0]) << 3)
            | (u8::from(self.reserved_bits[1]) << 2)
            | (packet_number.vec_len() as u8 - 1)
    }

    fn header(&self) -> Vec<u8> {
        let packet_number = PacketNumber::from_u32(self.packet_number);
        let type_specific_half_byte = self.type_specific_half_byte();
        let first_byte = (1 << 7) // long header
            + (1 << 6) // packet fixed bit
            + (0 << 4) // initial packet
            + type_specific_half_byte;
        // tokenの長さはVarIntの取れる値の範囲になるので、unwrapしてよい
        let token_length = VarInt::try_new(self.token.len() as u64).unwrap();
        let token_length_bytes = token_length.to_vec();
        // remain_lengthはVarIntの撮れる範囲になるので、unwrapしてよい
        let remain_length =
            VarInt::try_new((packet_number.vec_len() + encrypted_len(self.payload.len())) as u64)
                .unwrap();
        let remain_length_bytes = remain_length.to_vec();
        [
            &[first_byte][..],
            &QuicVersion::Rfc9000.to_bytes()[..],
            &[self.destination_connection_id.len() as u8][..],
            &self.destination_connection_id,
            &[self.source_connection_id.len() as u8][..],
            &self.source_connection_id,
            &token_length_bytes,
            &self.token,
            &remain_length_bytes,
            &packet_number.to_vec(),
        ]
        .concat()
    }

    fn protect(
        &self,
        initial_destination_connection_id: &[u8],
        my_endpoint_type: &EndpointType,
    ) -> Result<LongHeaderPacket, ProtectError> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();

        let initial_secret = initial_secret(&initial_salt, initial_destination_connection_id);

        let encrypted_payload = encrypt(
            &initial_secret,
            &PacketNumber::from_u32(self.packet_number),
            my_endpoint_type,
            &self.header(),
            self.payload(),
        )?;

        let protect_packet_number = ProtectPacketNumberRfc9000::generate(
            &encrypted_payload,
            &PacketNumber::from_u32(self.packet_number),
            &initial_secret,
            my_endpoint_type,
        );

        let protect_type_specific_half_byte = ProtectTypeSpecificHalfByteRfc9000::generate(
            &encrypted_payload,
            &PacketNumber::from_u32(self.packet_number),
            self.type_specific_half_byte(),
            &initial_secret,
            my_endpoint_type,
        );

        let version_specific_data = {
            let mut version_specific_data = Vec::new();
            // tokenの長さはVarIntの範囲に収まる
            let token_length = VarInt::try_new(self.token.len() as u64).unwrap();
            let token_length_bytes = token_length.to_vec();
            let packet_number = PacketNumber::from_u32(self.packet_number);
            // remain_lengthの長さはVarIntの範囲に収まる
            let remain_length =
                VarInt::try_new((packet_number.vec_len() + encrypted_payload.len()) as u64)
                    .unwrap();
            let remain_length_bytes = remain_length.to_vec();

            version_specific_data.extend(token_length_bytes);
            version_specific_data.extend(remain_length_bytes);
            version_specific_data.extend(protect_packet_number.to_vec());
            version_specific_data.extend(&encrypted_payload);
            version_specific_data
        };

        Ok(LongHeaderPacket {
            fixed_bit: true,
            long_packet_type: super::LongPacketType::Initial,
            type_specific_bits: protect_type_specific_half_byte.to_raw_bits(),
            version: QuicVersion::Rfc9000,
            destination_connection_id: self.destination_connection_id.clone(),
            source_connection_id: self.source_connection_id.clone(),
            version_specific_data,
        })
    }

    fn unprotect(
        initial_destination_connection_id: &[u8],
        packet: &LongHeaderPacket,
        my_endpoint_type: &EndpointType,
    ) -> Result<(InitialPacketRfc9000, usize), UnprotectError> {
        if packet.long_packet_type != LongPacketType::Initial {
            return Err(UnprotectError::NotInitialPacket);
        }

        let initial_salt = QuicVersion::Rfc9000.initial_salt();

        let initial_secret = initial_secret(&initial_salt, initial_destination_connection_id);

        let (token_length, token, remain_length) = {
            let mut input = Cursor::new(&packet.version_specific_data);
            let token_length = input.read_var_int()?;
            let mut token = vec![0; token_length.u64() as usize];
            input.read_exact(&mut token)?;
            let remain_length = input.read_var_int()?;
            (token_length, token, remain_length)
        };

        let protect_type_specific_half_byte = ProtectTypeSpecificHalfByteRfc9000::new(
            type_specific_bits_to_half_byte(packet.type_specific_bits),
        );
        let packet_number_offset =
            token_length.len() + token_length.u64() as usize + remain_length.len();
        let type_specific_half_byte = protect_type_specific_half_byte.unprotect(
            &packet.version_specific_data,
            packet_number_offset,
            &initial_secret,
            &my_endpoint_type,
        );

        let packet_number_length = type_specific_half_byte.packet_number_length();
        let protect_packet_number = {
            let packet_number_bytes = packet
                .version_specific_data
                .get(packet_number_offset..packet_number_offset + packet_number_length)
                .ok_or(UnprotectError::UnexpectedEnd)?;
            // packet number bytes は必ずpacket numberがとれる値をとるので
            // unwrapしても問題ない
            ProtectPacketNumberRfc9000::try_from_bytes(packet_number_bytes).unwrap()
        };
        let packet_number = protect_packet_number.unprotect(
            &packet.version_specific_data,
            packet_number_offset,
            packet_number_length,
            &initial_secret,
            my_endpoint_type,
        );

        let encrypted_payload = packet
            .version_specific_data
            .get(
                packet_number_offset + packet_number_length
                    ..packet_number_offset + packet_number_length + remain_length.u64() as usize
                        - packet_number_length,
            )
            .ok_or(UnprotectError::UnexpectedEnd)?;

        let packet_header = {
            let first_byte = (1 << 7) // long header
            + (1 << 6) // packet fixed bit
            + (0 << 4) // initial packet
            + type_specific_half_byte.u8();
            [
                &[first_byte][..],
                &packet.version.to_bytes()[..],
                &[packet.destination_connection_id.len() as u8][..],
                &packet.destination_connection_id,
                &[packet.source_connection_id.len() as u8][..],
                &packet.source_connection_id,
                &token_length.to_vec(),
                &token,
                &remain_length.to_vec(),
                &packet_number.to_vec(),
            ]
            .concat()
        };
        let payload = decrypt(
            &initial_secret,
            &packet_number,
            my_endpoint_type,
            &packet_header,
            encrypted_payload,
        )?;

        Ok((
            Self {
                reserved_bits: type_specific_half_byte.reserved_bits(),
                destination_connection_id: packet.destination_connection_id.clone(),
                source_connection_id: packet.source_connection_id.clone(),
                token,
                packet_number: packet_number.u32(),
                payload,
            },
            packet_header.len() + remain_length.u64() as usize - packet_number.vec_len(),
        ))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum UnprotectError {
    #[error("no support version")]
    NoSupportVersion,
    #[error("std I/O")]
    StdIo(#[from] std::io::Error),
    #[error("unexpected end")]
    UnexpectedEnd,
    #[error("decrypt payload error")]
    DecryptError(#[from] DecryptError),
    #[error("not initial packet error")]
    NotInitialPacket,
}

#[derive(thiserror::Error, Debug)]
pub enum ProtectError {
    #[error("encrypt error")]
    EncryptError(#[from] crypto::EncryptError),
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct TypeSpecificHalfByteRfc9000(u8);

impl TypeSpecificHalfByteRfc9000 {
    fn new(u: u8) -> Self {
        Self(u)
    }

    fn packet_number_length(&self) -> usize {
        (self.0 & 0b11) as usize + 1
    }

    fn reserved_bits(&self) -> [bool; 2] {
        [(self.0 & 0b1000) == 0b1000, (self.0 & 0b0100) == 0b0100]
    }

    fn u8(&self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use refuic_common::{EndpointType, QuicVersion};

    use crate::{long::LongPacketType, LongHeaderPacket};

    use super::InitialPacketRfc9000;

    #[test]
    fn protect_and_unprotect_xargs_org_client_initial_0() -> Result<(), anyhow::Error> {
        let destination_connection_id =
            include_bytes!("./initial/test_data/xargs_org/initial_destination_connection_id.bin")
                .to_vec();
        let source_connection_id = include_bytes!(
            "./initial/test_data/xargs_org/client_initial_0/source_connection_id.bin"
        )
        .to_vec();
        let payload =
            include_bytes!("./initial/test_data/xargs_org/client_initial_0/payload.bin").to_vec();
        let client_initial = InitialPacketRfc9000 {
            reserved_bits: [false, false],
            destination_connection_id: destination_connection_id.clone(),
            source_connection_id: source_connection_id.clone(),
            token: vec![],
            packet_number: 0,
            payload,
        };

        // クライアント上でprotectする
        let protected_client_initial =
            client_initial.protect(&destination_connection_id, &EndpointType::Client)?;

        let encrypted_payload =
            include_bytes!("./initial/test_data/xargs_org/client_initial_0/encrypted_payload.bin");
        let long = LongHeaderPacket {
            fixed_bit: true,
            long_packet_type: LongPacketType::Initial,
            type_specific_bits: [true, true, false, true],
            version: QuicVersion::Rfc9000,
            destination_connection_id: destination_connection_id.clone(),
            source_connection_id,
            version_specific_data: [&[0], &[0x41, 0x03][..], &[0x98], encrypted_payload].concat(),
        };

        assert_eq!(protected_client_initial, long);

        // サーバー上でunprotectする
        let (unprotected_client_initial, original_length) = InitialPacketRfc9000::unprotect(
            &destination_connection_id,
            &long,
            &EndpointType::Server,
        )?;

        assert_eq!(unprotected_client_initial, client_initial);
        assert_eq!(original_length, long.vec_len());

        Ok(())
    }

    #[test]
    fn protect_and_unprotect_xargs_org_server_initial_0() -> Result<(), anyhow::Error> {
        let initial_destination_connection_id =
            include_bytes!("./initial/test_data/xargs_org/initial_destination_connection_id.bin");
        let source_connection_id = include_bytes!(
            "./initial/test_data/xargs_org/server_initial_0/source_connection_id.bin"
        )
        .to_vec();
        let destination_connection_id = include_bytes!(
            "./initial/test_data/xargs_org/server_initial_0/destination_connection_id.bin"
        )
        .to_vec();
        let payload =
            include_bytes!("./initial/test_data/xargs_org/server_initial_0/payload.bin").to_vec();
        let server_initial = InitialPacketRfc9000 {
            reserved_bits: [false, false],
            destination_connection_id: destination_connection_id.clone(),
            source_connection_id: source_connection_id.clone(),
            token: vec![],
            packet_number: 0,
            payload,
        };

        // サーバー上でprotectする
        let protected_server_initial =
            server_initial.protect(initial_destination_connection_id, &EndpointType::Server)?;

        let encrypted_payload =
            include_bytes!("./initial/test_data/xargs_org/server_initial_0/encrypted_payload.bin");
        let long = LongHeaderPacket {
            fixed_bit: true,
            long_packet_type: LongPacketType::Initial,
            type_specific_bits: [true, true, false, true],
            version: QuicVersion::Rfc9000,
            destination_connection_id,
            source_connection_id,
            version_specific_data: [&[0], &[0x40, 0x75][..], &[0x3a], encrypted_payload].concat(),
        };

        assert_eq!(protected_server_initial, long);

        // クライアント上でunprotectする
        let (unprotected_client_initial, original_length) = InitialPacketRfc9000::unprotect(
            initial_destination_connection_id,
            &long,
            &EndpointType::Client,
        )?;

        assert_eq!(unprotected_client_initial, server_initial);
        assert_eq!(original_length, long.vec_len());

        Ok(())
    }
}
