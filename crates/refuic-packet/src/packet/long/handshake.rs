use refuic_common::QuicVersion;
use refuic_tls::{
    cipher_suite::CipherSuite,
    handshake::{
        certificate::Certificate, certificate_verify::CertificateVerify,
        encrypted_extensions::EncryptedExtensions, finished::Finished,
    },
    signature_scheme::SignatureScheme,
};

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

fn _server_handshake(
    version: &QuicVersion,
    cert_signature_scheme: &SignatureScheme,
    cert_signature: &[u8],
    ch_to_sh_message: &[u8],
    cipher_suite: &CipherSuite,
    destination_connection_id: Vec<u8>,
    source_connection_id: Vec<u8>,
    packet_number: u32,
) -> Option<HandshakePacket> {
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2.1
    // The value included prior to protection MUST be set to 0
    // プロテクションされる前の値は0でなければならない
    let reserved_bits = [false, false];
    let version = version.clone();

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3-10
    // A QUIC endpoint MUST NOT reuse a packet number within the same packet number space in one connection.
    // らしいので、とりあえずパケットごとに一つずつ増やしてみる
    let packet_number = packet_number + 1;

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

            let certificate_verify = CertificateVerify::new(cert_signature_scheme, cert_signature);
            let crypto_frame = refuic_frame::frame::crypto::Frame::new(certificate_verify.to_vec());
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
        destination_connection_id,
        source_connection_id,
        packet_number,
        payload: payload,
    }))
}
