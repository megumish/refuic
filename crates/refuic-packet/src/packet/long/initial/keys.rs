use refuic_crypto::{
    hkdf_expand_label::{
        hkdf_expand_label_sha256_aes_128_key_len, hkdf_expand_label_sha256_aes_gcm_128_iv_len,
        hkdf_expand_label_sha256_aes_gcm_128_key_len,
    },
    hkdf_expand_label_sha256_sha256_len, hkdf_extract_sha256,
};

pub(super) fn initial_secret(
    initial_salt: &[u8],
    initial_destination_connection_id: &[u8],
) -> Vec<u8> {
    hkdf_extract_sha256(initial_salt, initial_destination_connection_id)
}

fn client_secret(initial_secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label_sha256_sha256_len(initial_secret, b"client in", b"")
}

fn server_secret(initial_secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label_sha256_sha256_len(initial_secret, b"server in", b"")
}

pub(super) fn client_key(initial_secret: &[u8]) -> Vec<u8> {
    let cs = client_secret(initial_secret);
    hkdf_expand_label_sha256_aes_gcm_128_key_len(&cs, b"quic key", b"")
}

pub(super) fn client_iv(initial_secret: &[u8]) -> Vec<u8> {
    let cs = client_secret(initial_secret);
    hkdf_expand_label_sha256_aes_gcm_128_iv_len(&cs, b"quic iv", b"")
}

pub(super) fn client_hp(initial_secret: &[u8]) -> Vec<u8> {
    let cs = client_secret(initial_secret);
    hkdf_expand_label_sha256_aes_128_key_len(&cs, b"quic hp", b"")
}

pub(super) fn server_key(initial_secret: &[u8]) -> Vec<u8> {
    let ss = server_secret(initial_secret);
    hkdf_expand_label_sha256_aes_gcm_128_key_len(&ss, b"quic key", b"")
}

pub(super) fn server_iv(initial_secret: &[u8]) -> Vec<u8> {
    let ss = server_secret(initial_secret);
    hkdf_expand_label_sha256_aes_gcm_128_iv_len(&ss, b"quic iv", b"")
}

pub(super) fn server_hp(initial_secret: &[u8]) -> Vec<u8> {
    let ss = server_secret(initial_secret);
    hkdf_expand_label_sha256_aes_128_key_len(&ss, b"quic hp", b"")
}

#[cfg(test)]
mod tests {
    use refuic_common::QuicVersion;

    #[test]
    fn get_client_key_v1() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");
        let initial_secret =
            super::initial_secret(&initial_salt, initial_destination_connection_id);

        let ck = super::client_key(&initial_secret);
        let expected = include_bytes!("./test_data/xargs_org/client_initial_key.bin");
        assert_eq!(&ck, expected);
        Ok(())
    }

    #[test]
    fn get_client_iv_v1() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");
        let initial_secret =
            super::initial_secret(&initial_salt, initial_destination_connection_id);

        let civ = super::client_iv(&initial_secret);
        let expected = include_bytes!("./test_data/xargs_org/client_initial_iv.bin");
        assert_eq!(&civ, expected);
        Ok(())
    }

    #[test]
    fn get_client_hp_v1() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");
        let initial_secret =
            super::initial_secret(&initial_salt, initial_destination_connection_id);

        let chp = super::client_hp(&initial_secret);
        let expected = include_bytes!("./test_data/xargs_org/client_initial_hp.bin");
        assert_eq!(&chp, expected);
        Ok(())
    }

    #[test]
    fn get_server_key_v1() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");
        let initial_secret =
            super::initial_secret(&initial_salt, initial_destination_connection_id);

        let ck = super::server_key(&initial_secret);
        let expected = include_bytes!("./test_data/xargs_org/server_initial_key.bin");
        assert_eq!(&ck, expected);
        Ok(())
    }

    #[test]
    fn get_server_iv_v1() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");
        let initial_secret =
            super::initial_secret(&initial_salt, initial_destination_connection_id);

        let civ = super::server_iv(&initial_secret);
        let expected = include_bytes!("./test_data/xargs_org/server_initial_iv.bin");
        assert_eq!(&civ, expected);
        Ok(())
    }

    #[test]
    fn get_server_hp_v1() -> Result<(), anyhow::Error> {
        let initial_salt = QuicVersion::Rfc9000.initial_salt();
        let initial_destination_connection_id =
            include_bytes!("./test_data/xargs_org/initial_destination_connection_id.bin");
        let initial_secret =
            super::initial_secret(&initial_salt, initial_destination_connection_id);

        let chp = super::server_hp(&initial_secret);
        let expected = include_bytes!("./test_data/xargs_org/server_initial_hp.bin");
        assert_eq!(&chp, expected);
        Ok(())
    }
}
