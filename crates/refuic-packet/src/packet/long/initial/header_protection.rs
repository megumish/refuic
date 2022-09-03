use refuic_common::EndpointType;
use refuic_crypto::aes_128_encrypt;

use crate::packet_number::PacketNumber;

use super::{
    keys::{client_hp, server_hp},
    TypeSpecificHalfByteRfc9000,
};

#[derive(Debug, PartialEq, Clone)]
pub(super) struct ProtectPacketNumberRfc9000(u32);

impl ProtectPacketNumberRfc9000 {
    pub(super) fn generate(
        encrypted_payload: &[u8],
        packet_number: &PacketNumber,
        initial_secret: &[u8],
        my_endpoint_type: &EndpointType,
    ) -> Self {
        let mask = mask_rfc9000_protected(
            packet_number,
            initial_secret,
            my_endpoint_type,
            encrypted_payload,
        );

        // 長さはpacket_numberの範囲に納まる
        let mask_packet_number = PacketNumber::try_from_bytes(&mask[1..]).unwrap();

        Self(packet_number.u32() ^ mask_packet_number.u32())
    }

    pub(super) fn unprotect(
        &self,
        version_specific_data: &[u8],
        packet_number_offset: usize,
        packet_number_length: usize,
        initial_secret: &[u8],
        my_endpoint_type: &EndpointType,
    ) -> PacketNumber {
        let mask = mask_rfc9000_unprotected(
            packet_number_offset,
            initial_secret,
            my_endpoint_type,
            version_specific_data,
        );

        // 長さはpacket_numberの範囲に収まる
        let mask_protect_packet_number =
            ProtectPacketNumberRfc9000::try_from_bytes(&mask[1..1 + packet_number_length]).unwrap();
        PacketNumber::from_u32(self.u32() ^ mask_protect_packet_number.u32())
    }

    pub(super) fn to_vec(&self) -> Vec<u8> {
        if self.0 < (1 << 8) {
            (self.0 as u8).to_be_bytes().to_vec()
        } else if self.0 < (1 << 16) {
            (self.0 as u16).to_be_bytes().to_vec()
        } else if self.0 < (1 << 24) {
            self.0.to_be_bytes()[1..].to_vec()
        } else {
            self.0.to_be_bytes().to_vec()
        }
    }

    pub(super) fn try_from_bytes(b: &[u8]) -> Result<Self, FromBytesError> {
        if b.is_empty() {
            return Err(FromBytesError);
        }
        Ok(if b.len() == 1 {
            ProtectPacketNumberRfc9000(b[0] as u32)
        } else if b.len() == 2 {
            ProtectPacketNumberRfc9000(u16::from_be_bytes([b[0], b[1]]) as u32)
        } else if b.len() == 3 {
            ProtectPacketNumberRfc9000(u32::from_be_bytes([0, b[0], b[1], b[2]]))
        } else {
            ProtectPacketNumberRfc9000(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        })
    }

    pub(super) fn u32(&self) -> u32 {
        self.0
    }
}

#[derive(thiserror::Error, Debug)]
#[error("from bytes error")]
pub(crate) struct FromBytesError;

#[derive(Debug, PartialEq, Clone)]
pub(super) struct ProtectTypeSpecificHalfByteRfc9000(u8);

impl ProtectTypeSpecificHalfByteRfc9000 {
    pub(super) fn generate(
        encrypted_payload: &[u8],
        packet_number: &PacketNumber,
        type_specific_half_byte: u8,
        initial_secret: &[u8],
        my_endpoint_type: &EndpointType,
    ) -> Self {
        let mask = mask_rfc9000_protected(
            packet_number,
            initial_secret,
            my_endpoint_type,
            encrypted_payload,
        );

        let mask_type_specific_half_byte = mask[0] & 0b1111;
        Self(type_specific_half_byte ^ mask_type_specific_half_byte)
    }

    pub(super) fn to_raw_bits(&self) -> [bool; 4] {
        [
            self.0 >> 3 == 1,
            (self.0 >> 2) & 0b1 == 1,
            (self.0 >> 1) & 0b1 == 1,
            self.0 & 0b1 == 1,
        ]
    }

    pub(super) fn new(u: u8) -> Self {
        Self(u)
    }

    pub(super) fn unprotect(
        &self,
        version_specific_data: &[u8],
        packet_number_offset: usize,
        initial_secret: &[u8],
        my_endpoint_type: &EndpointType,
    ) -> TypeSpecificHalfByteRfc9000 {
        let mask = mask_rfc9000_unprotected(
            packet_number_offset,
            initial_secret,
            my_endpoint_type,
            version_specific_data,
        );

        let mask_type_specific_half_byte = mask[0] & 0b1111;
        TypeSpecificHalfByteRfc9000::new(self.0 ^ mask_type_specific_half_byte)
    }
}

fn mask_rfc9000_protected(
    packet_number: &PacketNumber,
    initial_secret: &[u8],
    my_endpoint_type: &EndpointType,
    encrypted_payload: &[u8],
) -> Vec<u8> {
    // protect するときは自身のパケットに適用すると仮定するので
    // 自分のエンドポイントタイプに合わせてHP Keyを取得する。
    let hp_key = match my_endpoint_type {
        EndpointType::Client => client_hp(initial_secret),
        EndpointType::Server => server_hp(initial_secret),
    };

    let sample = {
        let offset = 4 - packet_number.vec_len();
        &encrypted_payload[offset..offset + hp_key.len()]
    };

    aes_128_encrypt(&hp_key, sample)[0..1 + packet_number.vec_len()].to_vec()
}

fn mask_rfc9000_unprotected(
    packet_number_offset: usize,
    initial_secret: &[u8],
    my_endpoint_type: &EndpointType,
    version_specific_data: &[u8],
) -> Vec<u8> {
    // unprotect するときは相手のパケットに適用すると仮定するので
    // 自分と逆のエンドポイントタイプに合わせてHP Keyを取得する。
    let hp_key = match my_endpoint_type {
        EndpointType::Client => server_hp(initial_secret),
        EndpointType::Server => client_hp(initial_secret),
    };

    let sample_offset = packet_number_offset + 4;
    let sample = &version_specific_data[sample_offset..sample_offset + hp_key.len()];

    aes_128_encrypt(&hp_key, sample)[0..1 + PacketNumber::max_vec_len()].to_vec()
}

#[cfg(test)]
mod tests {
    use refuic_common::{EndpointType, QuicVersion};

    use crate::{long::initial::keys::initial_secret, packet_number::PacketNumber};

    use super::{ProtectPacketNumberRfc9000, ProtectTypeSpecificHalfByteRfc9000};

    #[test]
    fn protect_packet_number_xargs_org_client_initial_0() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");

        let initial_secret = initial_secret(&initial_salt, initial_destination_connection_id);
        let protect_packet_number = ProtectPacketNumberRfc9000::generate(
            include_bytes!("./test_data/xargs_org/client_initial_0/encrypted_payload.bin"),
            &PacketNumber::from_u32(0),
            &initial_secret,
            &EndpointType::Client,
        );

        assert_eq!(protect_packet_number.0, 0x98);

        Ok(())
    }

    #[test]
    fn protect_type_specific_half_byte_xargs_org_client_initial_0() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");

        let initial_secret = initial_secret(&initial_salt, initial_destination_connection_id);
        let protect_type_sepcific_half_byte = ProtectTypeSpecificHalfByteRfc9000::generate(
            include_bytes!("./test_data/xargs_org/client_initial_0/encrypted_payload.bin"),
            &PacketNumber::from_u32(0),
            0,
            &initial_secret,
            &EndpointType::Client,
        );

        assert_eq!(protect_type_sepcific_half_byte.0, 0xd);

        Ok(())
    }
}
