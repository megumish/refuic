use std::io::{Cursor, Read};

use immic_common::{EndpointType, QuicVersion, ReadVarInt};
use immic_crypto::{
    aes_128_encrypt, aes_128_gcm_decrypt, aes_128_gcm_key_len, Aes128GcmDecryptError,
};

use crate::{long::type_specific_bits_to_half_byte, packet::get_key_iv_hp_v1};

use super::{LongHeaderPacket, LongPacketType};

pub fn remove_protection(
    packet: &LongHeaderPacket,
    version: &QuicVersion,
    endpoint_type: &EndpointType,
) -> Result<LongHeaderPacket, RemoveProtectionError> {
    match version {
        QuicVersion::Rfc9000 => remove_protection_v1(packet, endpoint_type),
        _ => Err(RemoveProtectionError::NoSupportVersion),
    }
}

fn remove_protection_v1(
    packet: &LongHeaderPacket,
    endpoint_type: &EndpointType,
) -> Result<LongHeaderPacket, RemoveProtectionError> {
    match packet.long_packet_type {
        LongPacketType::Initial => remove_protection_v1_for_initial(packet, endpoint_type),
        _ => unimplemented!(),
    }
}

fn remove_protection_v1_for_initial(
    packet: &LongHeaderPacket,
    endpoint_type: &EndpointType,
) -> Result<LongHeaderPacket, RemoveProtectionError> {
    let initial_salt = QuicVersion::Rfc9000.initial_salt();

    let (key, iv, hp) = {
        let (label, client_destination_connection_id) = match endpoint_type {
            EndpointType::Server =>
            // server received a client packet
            {
                ("client in".as_bytes(), &packet.destination_connection_id)
            }
            EndpointType::Client =>
            // client received a server packet
            {
                ("server in".as_bytes(), &packet.source_connection_id)
            }
        };

        get_key_iv_hp_v1(label, client_destination_connection_id, &initial_salt)
    };

    let (packet_number_offset, remain_length, token_length, token) = {
        let mut input = Cursor::new(&packet.version_specific_data);
        let token_length = input.read_var_int()?;
        let mut token = vec![0; token_length.u64() as usize];
        input.read_exact(&mut token)?;
        let remain_length = input.read_var_int()?;
        (
            token_length.len() + token_length.u64() as usize + remain_length.len(),
            remain_length,
            token_length,
            token,
        )
    };

    let sample_offset = packet_number_offset + 4;
    let sample =
        &packet.version_specific_data[sample_offset..sample_offset + aes_128_gcm_key_len()];

    let mask = aes_128_encrypt(&hp, sample);

    let mut unprotected_packet = packet.clone();
    let unprotected_type_specific_half_byte = {
        let type_specific_half_byte = type_specific_bits_to_half_byte(packet.type_specific_bits);
        type_specific_half_byte ^ (mask[0] & 0b1111)
    };
    {
        let mut unprotected_type_specific_bits = [false; 4];
        unprotected_type_specific_bits[0] = ((unprotected_type_specific_half_byte >> 3) & 1) == 1;
        unprotected_type_specific_bits[1] = ((unprotected_type_specific_half_byte >> 2) & 1) == 1;
        unprotected_type_specific_bits[2] = ((unprotected_type_specific_half_byte >> 1) & 1) == 1;
        unprotected_type_specific_bits[3] = ((unprotected_type_specific_half_byte >> 0) & 1) == 1;
        unprotected_packet.type_specific_bits = unprotected_type_specific_bits;
    }

    let packet_number_length = ((unprotected_type_specific_half_byte & 0b0011) as usize) + 1;

    let packet_number_bytes = unprotected_packet
        .version_specific_data
        .get_mut(packet_number_offset..packet_number_offset + packet_number_length)
        .ok_or(RemoveProtectionError::UnexpectedEnd)?;
    {
        let mut count = 0;
        for b in packet_number_bytes {
            *b = *b ^ mask[count + 1];
            count += 1;
        }
    }

    let packet_number_bytes = unprotected_packet
        .version_specific_data
        .get(packet_number_offset..packet_number_offset + packet_number_length)
        .ok_or(RemoveProtectionError::UnexpectedEnd)?;

    // https://www.rfc-editor.org/rfc/rfc9001#section-5.3-5
    // nonce は iv と packet number bytes の XOR で作られる
    let nonce = std::iter::repeat(&0)
        .take(iv.len() - packet_number_length)
        .chain(packet_number_bytes.iter())
        .zip(iv.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let (packet_header, packet_payload) = {
        let mut packet_header = Vec::new();
        let first_byte = (1 << 7)
            + ((packet.fixed_bit as u8) << 6)
            + (0 << 4)
            + unprotected_type_specific_half_byte;
        packet_header.push(first_byte);
        packet_header.extend(packet.version.to_bytes());
        packet_header.push(packet.destination_connection_id.len() as u8);
        packet_header.extend(&packet.destination_connection_id);
        packet_header.push(packet.source_connection_id.len() as u8);
        packet_header.extend(&packet.source_connection_id);
        let version_specific_data_offset = packet_header.len();
        packet_header.extend(&unprotected_packet.version_specific_data);
        (
            packet_header
                [0..version_specific_data_offset + packet_number_offset + packet_number_length]
                .to_owned(),
            packet_header
                [version_specific_data_offset + packet_number_offset + packet_number_length..version_specific_data_offset + packet_number_offset + remain_length.u64() as usize]
                .to_owned(),
        )
    };

    let decrypted_payload = aes_128_gcm_decrypt(&key, &nonce, &packet_header, &packet_payload)?;

    unprotected_packet.version_specific_data = {
        let token_length_bytes = token_length.to_vec();
        let remain_length_bytes = remain_length.to_vec();
        [
            &token_length_bytes[..],
            &token[..],
            &remain_length_bytes[..],
            &packet_number_bytes[..],
            &decrypted_payload[..],
        ]
        .concat()
    };

    Ok(unprotected_packet)
}

#[derive(thiserror::Error, Debug)]
pub enum RemoveProtectionError {
    #[error("no support version")]
    NoSupportVersion,
    #[error("std I/O")]
    StdIo(#[from] std::io::Error),
    #[error("unexpected end")]
    UnexpectedEnd,
    #[error("decrypt payload error")]
    Aes128GcmDecryptError(#[from] Aes128GcmDecryptError),
}
