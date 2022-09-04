use std::net::SocketAddr;

pub trait Socket {
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), RecvError>;
}

#[derive(thiserror::Error, Debug)]
pub enum RecvError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}
