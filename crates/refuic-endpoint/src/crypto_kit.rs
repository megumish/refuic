use refuic_tls::{
    cipher_suite::CipherSuite,
    extension::{
        key_share::KeyShareEntry, psk_key_exchange_modes::PskKeyExchangeMode,
        server_name::ServerName, supported_versions::Version as TlsVersion,
    },
    named_curve::NamedCurve,
    signature_scheme::SignatureScheme,
};

use crate::repository::RepositoryError;

pub trait CryptoKitRepository {
    fn update(&self, connection_id: &[u8], crypto_kit: &CryptoKit) -> Result<(), RepositoryError>;

    fn crypto_kit(&self, connection_id: &[u8]) -> Result<CryptoKit, RepositoryError>;
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CryptoKit {
    client_cipher_suites: Vec<CipherSuite>,
    cipher_suite: Option<CipherSuite>,

    client_server_names: Vec<ServerName>,
    certificate_server_names: Vec<Vec<u8>>,
    server_name: Option<Vec<u8>>,

    client_named_curves: Vec<NamedCurve>,
    named_curve: Option<NamedCurve>,

    client_signature_algorithms: Vec<SignatureScheme>,
    signature_algorithm: Option<SignatureScheme>,

    client_key_shares: Vec<KeyShareEntry>,
    client_secret_keys: Vec<Vec<u8>>,
    client_key_share: Option<KeyShareEntry>,
    server_key_share: Option<KeyShareEntry>,
    client_secret_key: Option<KeyShareEntry>,
    server_secret_key: Option<Vec<u8>>,

    client_psk_key_exchange_modes: Vec<PskKeyExchangeMode>,
    psk_key_exchange_mode: Option<PskKeyExchangeMode>,

    client_supported_versions: Vec<TlsVersion>,
    supported_version: Option<TlsVersion>,
}

impl CryptoKit {
    pub fn new() -> Self {
        Default::default()
    }

    pub(crate) fn updated_client_cipher_suites(&mut self, client_cipher_suites: &[CipherSuite]) {
        self.client_cipher_suites = client_cipher_suites.to_owned();
    }
    pub(crate) fn negotiated_cipher_suite(&mut self) -> Result<(), NegotiationError> {
        for client_cipher_suite in &self.client_cipher_suites {
            for server_cipher_suite in server_cipher_suites() {
                if client_cipher_suite == &server_cipher_suite {
                    self.cipher_suite = Some(server_cipher_suite);
                    self.client_cipher_suites = Vec::new();
                    return Ok(());
                }
            }
        }
        Err(NegotiationError::NoSupportCipherSuite)
    }
    pub(crate) fn acknowledged_cipher_suite(
        &mut self,
        server_cipher_suite: &CipherSuite,
    ) -> Result<(), AcknowledgeError> {
        if self.client_cipher_suites.contains(server_cipher_suite) {
            self.cipher_suite = Some(server_cipher_suite.clone());
            self.client_cipher_suites = Vec::new();
            Ok(())
        } else {
            return Err(AcknowledgeError::NoSupportCipherSuite);
        }
    }
    pub(crate) fn is_negotiated_cipher_suite(&self) -> bool {
        self.client_cipher_suites.is_empty() && self.cipher_suite.is_some()
    }
    pub(crate) fn is_acknowledged_cipher_suite(&self) -> bool {
        self.client_cipher_suites.is_empty() && self.cipher_suite.is_some()
    }

    pub(crate) fn updated_client_server_names(&mut self, server_names: &[ServerName]) {
        self.client_server_names = server_names.to_owned();
    }
    pub(crate) fn negotiated_server_name(&mut self) -> Result<(), NegotiationError> {
        for client_server_name in &self.client_server_names {
            for server_name in &self.certificate_server_names {
                if client_server_name.name() == server_name {
                    self.server_name = Some(server_name.clone());
                    self.client_server_names = Vec::new();
                    return Ok(());
                }
            }
        }
        Err(NegotiationError::NoCertificateServerName)
    }
    pub(crate) fn is_negotiated_server_name(&self) -> bool {
        self.client_server_names.is_empty() && self.server_name.is_some()
    }

    pub(crate) fn updated_client_named_curves(&mut self, client_named_curves: &[NamedCurve]) {
        self.client_named_curves = client_named_curves.to_owned();
    }
    pub(crate) fn negotiated_named_curve(&mut self) -> Result<(), NegotiationError> {
        for client_named_curve in &self.client_named_curves {
            for server_named_curve in server_named_curves() {
                if client_named_curve == &server_named_curve {
                    self.named_curve = Some(server_named_curve);
                    self.client_named_curves = Vec::new();
                    return Ok(());
                }
            }
        }
        Err(NegotiationError::NoSupportNamedCurve)
    }
    pub(crate) fn is_negotiated_named_curve(&self) -> bool {
        self.client_named_curves.is_empty() && self.named_curve.is_some()
    }

    pub(crate) fn updated_client_signature_algorithms(
        &mut self,
        client_signature_algorithms: &[SignatureScheme],
    ) {
        self.client_signature_algorithms = client_signature_algorithms.to_owned();
    }
    pub(crate) fn negotiated_signature_algorithm(&mut self) -> Result<(), NegotiationError> {
        for client_signature_algorithm in &self.client_signature_algorithms {
            for server_signature_algorithm in server_signature_algorithms() {
                if client_signature_algorithm == &server_signature_algorithm {
                    self.signature_algorithm = Some(server_signature_algorithm);
                    self.client_signature_algorithms = Vec::new();
                    return Ok(());
                }
            }
        }
        Err(NegotiationError::NoSupportSignatureAlgorithm)
    }
    pub(crate) fn is_negotiated_signature_algorithm(&self) -> bool {
        self.client_signature_algorithms.is_empty() && self.signature_algorithm.is_some()
    }

    pub(crate) fn updated_client_key_shares(&mut self, client_key_shares: &[KeyShareEntry]) {
        self.client_key_shares = client_key_shares.to_owned();
    }
    pub(crate) fn negotiated_key_shares(&mut self) -> Result<(), NegotiationError> {
        for client_key_share in &self.client_key_shares {
            if server_named_curves().contains(client_key_share.named_group()) {
                self.client_key_share = Some(client_key_share.clone());
                self.client_key_shares = Vec::new();
                break;
            }
        }
        if let Some(client_key_share) = &self.client_key_share {
            let (key_share, secret_key) = KeyShareEntry::new(client_key_share.named_group());
            self.server_key_share = Some(key_share);
            self.server_secret_key = Some(secret_key);
            Ok(())
        } else {
            Err(NegotiationError::NoSupportClientKeyShare)
        }
    }
    pub(crate) fn is_negotiated_client_key_share(&self) -> bool {
        self.client_key_shares.is_empty()
            && self.client_key_share.is_some()
            && self.server_key_share.is_some()
            && self.server_secret_key.is_some()
    }

    pub(crate) fn updated_client_psk_key_exchange_modes(
        &mut self,
        client_psk_key_exchange_modes: &[PskKeyExchangeMode],
    ) {
        self.client_psk_key_exchange_modes = client_psk_key_exchange_modes.to_owned();
    }
    pub(crate) fn updated_psk_key_exchange_mode(
        &mut self,
        psk_key_exchange_mode: PskKeyExchangeMode,
    ) {
        self.psk_key_exchange_mode = Some(psk_key_exchange_mode);
    }
    pub(crate) fn negotiated_psk_key_exchange_mode(&mut self) -> Result<(), NegotiationError> {
        for client_psk_key_exchange_mode in &self.client_psk_key_exchange_modes {
            for server_psk_key_exchange_mode in server_psk_key_exchange_modes() {
                if client_psk_key_exchange_mode == &server_psk_key_exchange_mode {
                    self.psk_key_exchange_mode = Some(server_psk_key_exchange_mode);
                    self.client_psk_key_exchange_modes = Vec::new();
                    return Ok(());
                }
            }
        }
        Err(NegotiationError::NoSupportPskKeyExchangeMode)
    }
    pub(crate) fn is_negotiated_psk_key_exchange_mode(&self) -> bool {
        self.client_psk_key_exchange_modes.is_empty() && self.psk_key_exchange_mode.is_some()
    }

    pub(crate) fn updated_client_supported_versions(
        &mut self,
        client_supported_versions: &[TlsVersion],
    ) {
        self.client_supported_versions = client_supported_versions.to_owned();
    }
    pub(crate) fn updated_supported_version(&mut self, supported_version: &TlsVersion) {
        self.supported_version = Some(supported_version.clone());
    }
    pub(crate) fn negotiated_supported_version(&mut self) -> Result<(), NegotiationError> {
        for client_suported_version in &self.client_supported_versions {
            for server_supported_version in server_supported_versions() {
                if client_suported_version == &server_supported_version {
                    self.supported_version = Some(server_supported_version);
                    self.client_supported_versions = Vec::new();
                    return Ok(());
                }
            }
        }
        Err(NegotiationError::NoSupportPskKeyExchangeMode)
    }
    pub(crate) fn is_negotiated_supported_version(&self) -> bool {
        self.client_supported_versions.is_empty() && self.supported_version.is_some()
    }
}

fn server_cipher_suites() -> [CipherSuite; 1] {
    [CipherSuite::TlsAes128GcmSha256]
}

fn server_named_curves() -> [NamedCurve; 1] {
    [NamedCurve::X25519]
}

fn server_signature_algorithms() -> [SignatureScheme; 1] {
    [SignatureScheme::EcdsaSecp256r1Sha256]
}

fn server_psk_key_exchange_modes() -> [PskKeyExchangeMode; 1] {
    [PskKeyExchangeMode::PskKeyWithDhe]
}

fn server_supported_versions() -> [TlsVersion; 1] {
    [TlsVersion::Tls1_3]
}

#[derive(thiserror::Error, Debug)]
pub enum NegotiationError {
    #[error("No support cipher suite")]
    NoSupportCipherSuite,
    #[error("No certificate server name")]
    NoCertificateServerName,
    #[error("No support named curve")]
    NoSupportNamedCurve,
    #[error("No support signature algorithm")]
    NoSupportSignatureAlgorithm,
    #[error("No support client key share")]
    NoSupportClientKeyShare,
    #[error("No support psk key exchange mode")]
    NoSupportPskKeyExchangeMode,
}

#[derive(thiserror::Error, Debug)]
pub enum AcknowledgeError {
    #[error("No support cipher suite")]
    NoSupportCipherSuite,
}
