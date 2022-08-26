use refuic_common::EndpointType;
use refuic_crypto::{
    aes_128_gcm_decrypt, aes_128_gcm_encrypt, Aes128GcmDecryptError, Aes128GcmEncryptError,
};

use crate::packet_number::PacketNumber;

use super::keys::{client_iv, client_key, server_iv, server_key};

pub(super) fn encrypt(
    initial_secret: &[u8],
    packet_number: &PacketNumber,
    my_endpoint_type: &EndpointType,
    packet_header: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    // encrypt するときは自身のパケットに適用すると仮定するので
    // 自分のエンドポイントタイプに合わせてIVを取得する。
    let iv = match my_endpoint_type {
        EndpointType::Client => client_iv(initial_secret),
        EndpointType::Server => server_iv(initial_secret),
    };
    let nonce = nonce(&iv, packet_number);

    // encrypt するときは自身のパケットに適用すると仮定するので
    // 自分のエンドポイントタイプに合わせてKeyを取得する。
    let key = match my_endpoint_type {
        EndpointType::Client => client_key(initial_secret),
        EndpointType::Server => server_key(initial_secret),
    };

    Ok(aes_128_gcm_encrypt(&key, &nonce, &packet_header, &payload)?)
}

pub(super) fn decrypt(
    initial_secret: &[u8],
    packet_number: &PacketNumber,
    my_endpoint_type: &EndpointType,
    packet_header: &[u8],
    encrypted_payload: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    // encrypt するときは自身のパケットに適用すると仮定するので
    // 自分のエンドポイントタイプに合わせてIVを取得する。
    let iv = match my_endpoint_type {
        EndpointType::Client => client_iv(initial_secret),
        EndpointType::Server => server_iv(initial_secret),
    };
    let nonce = nonce(&iv, packet_number);

    // encrypt するときは自身のパケットに適用すると仮定するので
    // 自分のエンドポイントタイプに合わせてKeyを取得する。
    let key = match my_endpoint_type {
        EndpointType::Client => client_key(initial_secret),
        EndpointType::Server => server_key(initial_secret),
    };

    Ok(aes_128_gcm_decrypt(
        &key,
        &nonce,
        &packet_header,
        &encrypted_payload,
    )?)
}

/// https://www.rfc-editor.org/rfc/rfc9001#section-5.3-5
/// nonce は iv と packet number bytes の XOR で作られる
fn nonce(iv: &[u8], packet_number: &PacketNumber) -> Vec<u8> {
    std::iter::repeat(&0)
        .take(iv.len() - packet_number.vec_len())
        .chain(packet_number.to_vec().iter())
        .zip(iv.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

#[derive(thiserror::Error, Debug)]
#[error("encrypt error")]
pub enum EncryptError {
    #[error("aes 128 gcm encrypt error")]
    Aes128GcmEncryptError(#[from] Aes128GcmEncryptError),
}

#[derive(thiserror::Error, Debug)]
#[error("decrypt error")]
pub enum DecryptError {
    #[error("aes 128 gcm decrypt error")]
    Aes128GcmEncryptError(#[from] Aes128GcmDecryptError),
}

#[cfg(test)]
mod tests {
    use refuic_common::{EndpointType, QuicVersion};

    use crate::{
        long::initial::{crypto::decrypt, keys::initial_secret},
        packet_number::PacketNumber,
    };

    use super::encrypt;

    #[test]
    fn encrypt_xargs_org_client_initial_packet() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");

        let initial_secret = initial_secret(&initial_salt, initial_destination_connection_id);

        let encrypted_payload = encrypt(
            &initial_secret,
            &PacketNumber::from_u32(0),
            &EndpointType::Client,
            include_bytes!("./test_data/xargs_org/client_initial_0/packet_header.bin"),
            include_bytes!("./test_data/xargs_org/client_initial_0/payload.bin"),
        )?;
        assert_eq!(
            &encrypted_payload,
            include_bytes!("./test_data/xargs_org/client_initial_0/encrypted_payload.bin")
        );
        Ok(())
    }

    #[test]
    fn decrypt_xargs_org_client_initial_packet() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");

        let initial_secret = initial_secret(&initial_salt, initial_destination_connection_id);

        let payload = decrypt(
            &initial_secret,
            &PacketNumber::from_u32(0),
            &EndpointType::Client,
            include_bytes!("./test_data/xargs_org/client_initial_0/packet_header.bin"),
            include_bytes!("./test_data/xargs_org/client_initial_0/encrypted_payload.bin"),
        )?;
        assert_eq!(
            &payload,
            include_bytes!("./test_data/xargs_org/client_initial_0/payload.bin")
        );
        Ok(())
    }
}
