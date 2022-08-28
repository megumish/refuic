use std::net::SocketAddr;

pub trait SocketRfc9000 {
    fn new<A>(addr: A) -> Self
    where
        A: Into<SocketAddr>;
}
