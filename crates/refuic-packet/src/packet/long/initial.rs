use std::io::{Cursor, Read};

use refuic_common::{var_int::VarInt, EndpointType, QuicVersion, ReadVarInt};
use refuic_crypto::{
    aes_128_encrypt, aes_128_gcm_decrypt, aes_128_gcm_encrypted_len, aes_128_gcm_key_len,
    hkdf_expand_label::{
        hkdf_expand_label_sha256_aes_gcm_128_iv_len, hkdf_expand_label_sha256_aes_gcm_128_key_len,
    },
    hkdf_expand_label_sha256_sha256_len, hkdf_extract_sha256, Aes128GcmDecryptError,
};
use refuic_tls::{
    cipher_suite::CipherSuite,
    handshake::{
        certificate::Certificate, certificate_verify::CertificateVerify,
        encrypted_extensions::EncryptedExtensions, finished::Finished,
    },
    signature_scheme::SignatureScheme,
};

mod crypto;
mod endpoint_client;
mod endpoint_server;
mod header_protection;
mod keys;

pub use endpoint_client::ClientInitialPacket;
pub use endpoint_server::ServerInitialPacket;

use crate::packet_number::PacketNumber;

use self::{
    crypto::encrypt,
    header_protection::{ProtectPacketNumberRfc9000, ProtectTypeSpecificHalfByte},
    keys::initial_secret,
};

use super::{
    handshake::{HandshakePacket, HandshakePacketRfc9000},
    type_specific_bits_to_half_byte, LongHeaderPacket, LongHeaderPacketTransform, LongPacketType,
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

    pub fn protect(&self, endpoint_type: &EndpointType) -> Result<LongHeaderPacket, ProtectError> {
        match self {
            Self::Rfc9000(p) => p.protect(endpoint_type),
        }
    }

    pub fn server_handshake(
        &self,
        cert_signature_scheme: &SignatureScheme,
        cert_signature: &[u8],
        ch_to_sh_message: &[u8],
        cipher_suite: &CipherSuite,
    ) -> Option<HandshakePacket> {
        match self {
            Self::Rfc9000(p) => p.server_handshake(
                cert_signature_scheme,
                cert_signature,
                ch_to_sh_message,
                cipher_suite,
            ),
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
    my_endpoint_type: &EndpointType,
) -> Result<InitialPacket, LongHeaderPacketTransform> {
    let long = super::parse_from_bytes(buf, version)?;
    let long = remove_protection(&long, version, my_endpoint_type)?;
    parse_from_long(&long, version)
}

/// この構造体はRFC9000の要件を満たしていることを仮定して扱ってよい
#[derive(Debug, PartialEq, Clone)]
pub struct InitialPacketRfc9000 {
    reserved_bits: [bool; 2],
    version: QuicVersion,
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
        let remain_length = VarInt::try_new(
            // TODO: encrypted_len の長さ間違ってるかも
            (packet_number.vec_len() + aes_128_gcm_encrypted_len(self.payload.len())) as u64,
        )
        .unwrap();
        let remain_length_bytes = remain_length.to_vec();
        [
            &[first_byte][..],
            &self.version.to_bytes()[..],
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

    // serverで生成されたInitial Packetを使うことを暗黙的に仮定している。
    fn server_handshake(
        &self,
        cert_signature_scheme: &SignatureScheme,
        cert_signature: &[u8],
        ch_to_sh_message: &[u8],
        cipher_suite: &CipherSuite,
    ) -> Option<HandshakePacket> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2.1
        // The value included prior to protection MUST be set to 0
        // プロテクションされる前の値は0でなければならない
        let reserved_bits = [false, false];
        // ここでversionをClient Initial Packetからとってるのは不適切かもしれない
        let version = self.version.clone();

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3-10
        // A QUIC endpoint MUST NOT reuse a packet number within the same packet number space in one connection.
        // らしいので、とりあえずパケットごとに一つずつ増やしてみる
        let payload = {
            let mut payload = Vec::new();
            {
                let encrypted_extensions = EncryptedExtensions::new();
                let crypto_frame =
                    refuic_frame::frame::crypto::Frame::new(encrypted_extensions.to_vec());
                payload.extend(crypto_frame.to_vec());
            }
            {
                let certificate = Certificate::new();
                let crypto_frame = refuic_frame::frame::crypto::Frame::new(certificate.to_vec());
                payload.extend(crypto_frame.to_vec());

                let certificate_verify =
                    CertificateVerify::new(cert_signature_scheme, cert_signature);
                let crypto_frame =
                    refuic_frame::frame::crypto::Frame::new(certificate_verify.to_vec());
                payload.extend(crypto_frame.to_vec());

                let finished = Finished::new_server(
                    b"",
                    b"",
                    ch_to_sh_message,
                    &certificate,
                    &certificate_verify,
                    &cipher_suite,
                );
                let crypto_frame = refuic_frame::frame::crypto::Frame::new(finished.to_vec());
                payload.extend(crypto_frame.to_vec());
            }
            payload
        };

        Some(HandshakePacket::Rfc9000(HandshakePacketRfc9000 {
            reserved_bits,
            version,
            destination_connection_id: self.destination_connection_id.clone(),
            source_connection_id: self.source_connection_id.clone(),
            packet_number: self.packet_number,
            payload: payload,
        }))
    }

    fn protect(&self, my_endpoint_type: &EndpointType) -> Result<LongHeaderPacket, ProtectError> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();

        let initial_destination_connection_id = match my_endpoint_type {
            EndpointType::Server => &self.source_connection_id,
            EndpointType::Client => &self.destination_connection_id,
        };
        let initial_secret = initial_secret(&initial_salt, initial_destination_connection_id);

        let encrypted_payload = encrypt(
            &initial_secret,
            &PacketNumber::from_u32(self.packet_number),
            my_endpoint_type,
            &self.header(),
            self.payload(),
        )?;

        let protect_packet_number = ProtectPacketNumberRfc9000::new(
            &encrypted_payload,
            &PacketNumber::from_u32(self.packet_number),
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

        let protect_type_specific_half_byte = ProtectTypeSpecificHalfByte::new(
            &encrypted_payload,
            &PacketNumber::from_u32(self.packet_number),
            self.type_specific_half_byte(),
            &initial_secret,
            my_endpoint_type,
        );

        Ok(LongHeaderPacket {
            fixed_bit: true,
            long_packet_type: super::LongPacketType::Initial,
            type_specific_bits: protect_type_specific_half_byte.to_raw_bits(),
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

pub fn get_key_iv_hp_v1(
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

#[derive(thiserror::Error, Debug)]
pub enum ProtectError {
    #[error("encrypt error")]
    EncryptError(#[from] crypto::EncryptError),
}

#[cfg(test)]
mod tests {
    use refuic_common::{EndpointType, QuicVersion};

    use crate::{long::LongPacketType, LongHeaderPacket};

    use super::InitialPacketRfc9000;

    #[test]
    fn protect_xargs_org_client_initial_0() -> Result<(), anyhow::Error> {
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
            version: QuicVersion::Rfc9000,
            destination_connection_id: destination_connection_id.clone(),
            source_connection_id: source_connection_id.clone(),
            token: vec![],
            packet_number: 0,
            payload,
        };

        let protected_client_initial = client_initial.protect(&EndpointType::Client)?;

        let encrypted_payload =
            include_bytes!("./initial/test_data/xargs_org/client_initial_0/encrypted_payload.bin");
        let expected = LongHeaderPacket {
            fixed_bit: true,
            long_packet_type: LongPacketType::Initial,
            type_specific_bits: [true, true, false, true],
            version: QuicVersion::Rfc9000,
            destination_connection_id,
            source_connection_id,
            version_specific_data: [&[0], &[0x41, 0x03][..], &[0x98], encrypted_payload].concat(),
        };

        assert_eq!(protected_client_initial, expected);

        Ok(())
    }
}
