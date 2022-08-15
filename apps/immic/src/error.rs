#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("std I/O Error")]
    StdIo(#[from] std::io::Error),
    #[error("packet read error")]
    PacketReadError(#[from] immic_packet::PacketReadError),
    #[error("packet transform error")]
    PacketTransformError(#[from] immic_packet::PacketTransformError),
    #[error("long header packet transform error")]
    LongHeaderPacketTransform(#[from] immic_packet::long::LongHeaderPacketTransform),
    #[error("remove protection from long header packet error")]
    RemoveProtectionFromLongHeaderError(
        #[from] immic_packet::long::remove_protection::RemoveProtectionError,
    ),
    #[error("parse frame error")]
    ParseFrameError(#[from] immic_frame::frame::ParseFrameError),
    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),
}
