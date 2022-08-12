#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("std I/O Error")]
    StdIo(#[from] std::io::Error),
    #[error("packet read error")]
    PacketReadError(#[from] immic_packet::PacketReadError),
}
