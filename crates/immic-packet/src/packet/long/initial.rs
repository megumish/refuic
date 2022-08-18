use std::io::{Cursor, Read};

use immic_common::{var_int::VarInt, EndpointType, QuicVersion, ReadVarInt};
use immic_crypto::{
    aes_128_encrypt, aes_128_gcm_encrypt, aes_128_gcm_encrypted_len, aes_128_gcm_key_len,
};
use immic_tls::handshake::{client_hello::ClientHelloData, server_hello::ServerHelloData};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::packet::get_key_iv_hp_v1;

use super::{
    type_specific_bits_to_half_byte, type_specific_half_byte_to_bits, LongHeaderPacket,
    LongHeaderPacketTransform, ProtectError,
};

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

    pub fn server_initial(&self, client_hello_data: &ClientHelloData, key: &[u8]) -> InitialPacket {
        match self {
            Self::Rfc9000(p) => p.server_initial(client_hello_data, key),
        }
    }

    pub fn protect(&self, endpoint_type: &EndpointType) -> Result<LongHeaderPacket, ProtectError> {
        match self {
            Self::Rfc9000(p) => p.protect(endpoint_type),
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

pub fn parse_from_bytes(
    buf: &[u8],
    version: &QuicVersion,
    endpoint_type: &EndpointType,
) -> Result<InitialPacket, LongHeaderPacketTransform> {
    let long = super::parse_from_bytes(buf, version)?;
    let long = super::remove_protection(&long, version, endpoint_type)?;
    parse_from_long(&long, version)
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

    fn server_initial(&self, client_hello_data: &ClientHelloData, key: &[u8]) -> InitialPacket {
        let mut random_generator = StdRng::from_entropy();

        let source_connection_id = if self.destination_connection_id.is_empty() {
            // max connection id length is 20
            let mut buf = vec![0; 20];
            random_generator.fill_bytes(&mut buf);
            buf
        } else {
            self.destination_connection_id.clone()
        };
        let destination_connection_id = self.source_connection_id.clone();

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2.1
        // The value included prior to protection MUST be set to 0
        // プロテクションされる前の値は0でなければならない
        let reserved_bits = [false, false];
        // ここでversionをClient Initial Packetからとってるのは不適切かもしれない
        let version = self.version.clone();

        // TokenはRetry PacketかNew Token Frameを受け取った時しか使わない
        // のでここでは空にしておく
        let token = Vec::new();

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3-10
        // A QUIC endpoint MUST NOT reuse a packet number within the same packet number space in one connection.
        // らしいので、とりあえずパケットごとに一つずつ増やしてみる
        let packet_number = self.packet_number + 1;

        let payload = {
            let tls_server_hello = ServerHelloData::new(client_hello_data, key);
            let crypto_frame = immic_frame::frame::crypto::Frame::new(tls_server_hello.to_vec());
            let ack_frame = immic_frame::frame::ack::Frame::new(packet_number - 1);
            let mut payload = Vec::new();
            payload.extend(crypto_frame.to_vec());
            payload.extend(ack_frame.to_vec());
            payload.extend(vec![0u8; 1200 - payload.len()]);
            payload
        };

        InitialPacket::Rfc9000(Self {
            reserved_bits,
            version,
            destination_connection_id,
            source_connection_id,
            token,
            packet_number,
            payload,
        })
    }

    fn protect(&self, endpoint_type: &EndpointType) -> Result<LongHeaderPacket, ProtectError> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();

        let (key, iv, hp) = {
            let (label, client_destination_connection_id) = match endpoint_type {
                EndpointType::Server => ("server in".as_bytes(), &self.source_connection_id),
                EndpointType::Client => ("client in".as_bytes(), &self.destination_connection_id),
            };

            get_key_iv_hp_v1(label, client_destination_connection_id, &initial_salt)
        };

        let packet_number_bytes = if self.packet_number < (1 << 8) {
            (self.packet_number as u8).to_be_bytes().to_vec()
        } else if self.packet_number < (1 << 16) {
            (self.packet_number as u16).to_be_bytes().to_vec()
        } else {
            (self.packet_number as u32).to_be_bytes().to_vec()
        };

        // https://www.rfc-editor.org/rfc/rfc9001#section-5.3-5
        // nonce は iv と packet number bytes の XOR で作られる
        let nonce = std::iter::repeat(&0)
            .take(iv.len() - packet_number_bytes.len())
            .chain(packet_number_bytes.iter())
            .zip(iv.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        let type_specific_half_byte = {
            let mut type_specific_bits = [false; 4];
            let packet_number_length_byte = packet_number_bytes.len() - 1;
            type_specific_bits[0] = self.reserved_bits[0];
            type_specific_bits[1] = self.reserved_bits[1];
            type_specific_bits[2] = if (packet_number_length_byte >> 1) == 1 {
                true
            } else {
                false
            };
            type_specific_bits[3] = if (packet_number_length_byte & 0b01) == 1 {
                true
            } else {
                false
            };
            let type_specific_half_byte = type_specific_bits_to_half_byte(type_specific_bits);
            type_specific_half_byte
        };

        let packet_header = {
            let mut packet_header = Vec::new();
            let first_byte = (1 << 7) // long header
                + (1 << 6) // packet fixed bit
                + (0 << 4) // initial packet
                + type_specific_half_byte;
            let token_length = VarInt::try_new(self.token.len() as u64)?;
            let token_length_bytes = token_length.to_vec();
            let remain_length = VarInt::try_new(
                (packet_number_bytes.len() + aes_128_gcm_encrypted_len(self.payload.len())) as u64,
            )?;
            let remain_length_bytes = remain_length.to_vec();
            packet_header.push(first_byte);
            packet_header.extend(self.version.to_bytes());
            packet_header.push(self.destination_connection_id.len() as u8);
            packet_header.extend(&self.destination_connection_id);
            packet_header.push(self.source_connection_id.len() as u8);
            packet_header.extend(&self.source_connection_id);
            packet_header.extend(token_length_bytes);
            packet_header.extend(&self.token);
            packet_header.extend(remain_length_bytes);
            packet_header.extend(&packet_number_bytes);
            packet_header
        };

        let encrypted_payload = aes_128_gcm_encrypt(&key, &nonce, &packet_header, &self.payload)?;

        let sample = {
            let mut sample = vec![0; aes_128_gcm_key_len()];
            let offset = 4 - packet_number_bytes.len();
            sample.clone_from_slice(&encrypted_payload[offset..offset + aes_128_gcm_key_len()]);
            sample
        };

        let mask = aes_128_encrypt(&hp, &sample);

        let protected_type_speicifc_half_byte = type_specific_half_byte ^ (mask[0] & 0b1111);
        let type_specific_bits = type_specific_half_byte_to_bits(protected_type_speicifc_half_byte);

        let protected_packet_number_bytes = {
            let mut packet_number_bytes = packet_number_bytes.clone();
            let mut count = 0;
            for b in &mut packet_number_bytes {
                *b = *b ^ mask[count + 1];
                count += 1;
            }
            packet_number_bytes
        };

        let version_specific_data = {
            let mut version_specific_data = Vec::new();
            let token_length = VarInt::try_new(self.token.len() as u64).unwrap();
            let token_length_bytes = token_length.to_vec();
            let remain_length =
                VarInt::try_new((packet_number_bytes.len() + encrypted_payload.len()) as u64)?;
            let remain_length_bytes = remain_length.to_vec();

            version_specific_data.extend(token_length_bytes);
            version_specific_data.extend(remain_length_bytes);
            version_specific_data.extend(protected_packet_number_bytes);
            version_specific_data.extend(encrypted_payload);
            version_specific_data
        };

        Ok(LongHeaderPacket {
            fixed_bit: true,
            long_packet_type: super::LongPacketType::Initial,
            type_specific_bits,
            version: self.version.clone(),
            destination_connection_id: self.destination_connection_id.clone(),
            source_connection_id: self.source_connection_id.clone(),
            version_specific_data,
        })
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
