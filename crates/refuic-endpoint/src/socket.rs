use std::net::SocketAddr;

pub trait Socket {
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), RecvError>;
    fn send_to(&self, buf: &[u8], target: &SocketAddr) -> Result<usize, SendError>;
}

#[derive(thiserror::Error, Debug)]
pub enum RecvError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum SendError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}
