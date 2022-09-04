use refuic_tls::{
    cipher_suite::CipherSuite,
    extension::{key_share, psk_key_exchange_modes, server_name::ServerName, supported_versions},
    named_curve::NamedCurve,
    signature_scheme::SignatureScheme,
};

use crate::repository::RepositoryError;

pub trait CryptoKitRepository {
    fn update_client_cipher_suites_v1(
        &self,
        connection_id: &[u8],
        cipher_suites: &[CipherSuite],
    ) -> Result<(), RepositoryError>;
    fn is_negotiated_cipher_suite_v1(&self, connection_id: &[u8]) -> Result<bool, RepositoryError>;

    fn update_client_server_names_v1(
        &self,
        connection_id: &[u8],
        server_names: &[ServerName],
    ) -> Result<(), RepositoryError>;
    fn is_negotiated_server_name_v1(&self, connection_id: &[u8]) -> Result<bool, RepositoryError>;

    fn update_client_named_curves_v1(
        &self,
        connection_id: &[u8],
        named_curves: &[NamedCurve],
    ) -> Result<(), RepositoryError>;
    fn is_negotiated_named_curve_v1(&self, connection_id: &[u8]) -> Result<bool, RepositoryError>;

    fn update_client_signature_algorithms_v1(
        &self,
        connection_id: &[u8],
        signature_algorithms: &[SignatureScheme],
    ) -> Result<(), RepositoryError>;
    fn is_negotiated_signature_algorithm_v1(
        &self,
        connection_id: &[u8],
    ) -> Result<bool, RepositoryError>;

    fn update_client_key_share_v1(
        &self,
        connection_id: &[u8],
        key_share_entries: &[key_share::KeyShareEntry],
    ) -> Result<(), RepositoryError>;
    fn is_negotiated_client_key_share_v1(
        &self,
        connection_id: &[u8],
    ) -> Result<bool, RepositoryError>;

    fn update_client_psk_key_exchange_modes_v1(
        &self,
        connection_id: &[u8],
        modes: &[psk_key_exchange_modes::PskKeyExchangeMode],
    ) -> Result<(), RepositoryError>;
    fn is_negotiated_psk_key_exchange_mode_v1(
        &self,
        connection_id: &[u8],
    ) -> Result<bool, RepositoryError>;

    fn update_client_supported_versions_v1(
        &self,
        connection_id: &[u8],
        modes: &[supported_versions::Version],
    ) -> Result<(), RepositoryError>;
    fn is_negotiated_supported_version_v1(
        &self,
        connection_id: &[u8],
    ) -> Result<bool, RepositoryError>;
}
