#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("std I/O Error")]
    StdIo(#[from] std::io::Error),
    #[error("packet read error")]
    PacketReadError(#[from] refuic_packet::PacketReadError),
    #[error("packet transform error")]
    PacketTransformError(#[from] refuic_packet::PacketTransformError),
    #[error("long header packet transform error")]
    LongHeaderPacketTransform(#[from] refuic_packet::long::LongHeaderPacketTransform),
    #[error("remove protection from long header packet error")]
    RemoveProtectionFromLongHeaderError(
        #[from] refuic_packet::long::initial::RemoveProtectionError,
    ),
    #[error("parse frame error")]
    ParseFrameError(#[from] refuic_frame::frame::ParseFrameError),
    #[error("crypto data error")]
    CryptoDataError(#[from] refuic_frame::frame::crypto::CryptoDataError),
    #[error("long header packet protection error")]
    LongHeaderPacketProtectError(#[from] refuic_packet::long::ProtectError),
    #[error("handshake transform error")]
    HandshakeTransformError(#[from] refuic_tls::handshake::HandshakeTransformError),
    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),
}
