use immic_common::QuicVersion;

#[derive(Debug, PartialEq, Clone)]
pub enum HandshakePacket {
    Rfc9000(HandshakePacketRfc9000),
}

#[derive(Debug, PartialEq, Clone)]
pub struct HandshakePacketRfc9000 {
    pub(super) reserved_bits: [bool; 2],
    pub(super) version: QuicVersion,
    pub(super) destination_connection_id: Vec<u8>,
    pub(super) source_connection_id: Vec<u8>,
    pub(super) packet_number: u32,
    pub(super) payload: Vec<u8>,
}
