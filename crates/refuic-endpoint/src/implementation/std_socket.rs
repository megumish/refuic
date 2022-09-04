use std::net::{SocketAddr, UdpSocket};

use crate::socket::{RecvError, SendError};

#[derive(Debug)]
pub struct Socket {
    socket_address: SocketAddr,
}

impl Socket {
    pub fn new(socket_address: SocketAddr) -> Self {
        Self { socket_address }
    }
}

impl crate::socket::Socket for Socket {
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), RecvError> {
        let sock = UdpSocket::bind(self.socket_address)?;
        let result = sock.recv_from(buf)?;
        Ok(result)
    }

    fn send_to(&self, buf: &[u8], target: &SocketAddr) -> Result<usize, SendError> {
        let sock = UdpSocket::bind(self.socket_address)?;
        let result = sock.send_to(buf, target)?;
        Ok(result)
    }
}
