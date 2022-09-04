use refuic_packet::packet_number::PacketNumber;

use crate::repository::RepositoryError;

pub trait ConnectionRepository {
    fn connection_v1(&self, connection_id: &[u8]) -> Result<ConnectionRfc9000, RepositoryError>;
    fn update_v1(
        &self,
        connection_id: &[u8],
        connection: &ConnectionRfc9000,
    ) -> Result<(), RepositoryError>;
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct ConnectionRfc9000 {
    server_hello_packet_number: Option<PacketNumber>,
    encrypted_extensions_packet_number: Option<PacketNumber>,
    certificate_packet_number: Option<PacketNumber>,
    certificate_verify_packet_number: Option<PacketNumber>,
    handshake_finished_packet_number: Option<PacketNumber>,

    my_initial_packet_number: Option<PacketNumber>,
    my_handshake_packet_number: Option<PacketNumber>,
    acknowledged_my_initial_packet_numbers: Vec<PacketNumber>,
    acknowledged_my_handshake_packet_number: Vec<PacketNumber>,
}

impl ConnectionRfc9000 {
    pub fn new() -> Self {
        Default::default()
    }

    pub(crate) fn is_sent_server_hello(&self) -> bool {
        self.server_hello_packet_number.is_some()
    }
    pub(crate) fn is_acknowlegded_server_hello(&self) -> bool {
        if let Some(server_hello_packet_number) = &self.server_hello_packet_number {
            self.acknowledged_my_initial_packet_numbers
                .contains(&server_hello_packet_number)
        } else {
            false
        }
    }
    pub(crate) fn sent_server_hello(&mut self) {
        let packet_number = if let Some(pn) = self.my_initial_packet_number() {
            pn.clone()
        } else {
            PacketNumber::new()
        };
        self.server_hello_packet_number = Some(packet_number.clone());
        self.my_initial_packet_number = Some(packet_number.next());
    }

    pub(crate) fn is_sent_encrypted_extensions(&self) -> bool {
        self.encrypted_extensions_packet_number.is_some()
    }
    pub(crate) fn is_acknowledged_encrypted_extensions(&self) -> bool {
        if let Some(encrypted_extensions_packet_number) = &self.encrypted_extensions_packet_number {
            self.acknowledged_my_handshake_packet_number
                .contains(&encrypted_extensions_packet_number)
        } else {
            false
        }
    }

    pub(crate) fn is_sent_certificate(&self) -> bool {
        self.certificate_packet_number.is_some()
    }
    pub(crate) fn is_acknowledged_certificate(&self) -> bool {
        if let Some(certificate_packet_number) = &self.certificate_packet_number {
            self.acknowledged_my_handshake_packet_number
                .contains(&certificate_packet_number)
        } else {
            false
        }
    }

    pub(crate) fn is_sent_certificate_verify(&self) -> bool {
        self.certificate_verify_packet_number.is_some()
    }
    pub(crate) fn is_acknowledged_certificate_verify(&self) -> bool {
        if let Some(certificate_verify_packet_number) = &self.certificate_verify_packet_number {
            self.acknowledged_my_handshake_packet_number
                .contains(&certificate_verify_packet_number)
        } else {
            false
        }
    }

    pub(crate) fn is_sent_handshake_finished(&self) -> bool {
        self.handshake_finished_packet_number.is_some()
    }
    pub(crate) fn is_acknowledged_handshake_finished(&self) -> bool {
        if let Some(handshake_finished_packet_number) = &self.handshake_finished_packet_number {
            self.acknowledged_my_handshake_packet_number
                .contains(&handshake_finished_packet_number)
        } else {
            false
        }
    }

    pub(crate) fn my_initial_packet_number(&self) -> &Option<PacketNumber> {
        &self.my_initial_packet_number
    }
    pub(crate) fn my_handshake_packet_number(&self) -> &Option<PacketNumber> {
        &self.my_handshake_packet_number
    }
}
