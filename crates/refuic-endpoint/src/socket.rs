use std::net::SocketAddr;

#[async_trait::async_trait]
pub trait Socket {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), RecvError>;
}

#[derive(thiserror::Error, Debug)]
pub enum RecvError {}
