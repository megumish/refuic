use self::{handshake::HandshakeContextRfc9000, initial::InitialContextRfc9000};

pub mod handshake;
pub mod initial;

pub trait ContextRfc9000 {
    fn new() -> Self;

    fn handshake_context(&self, id: &[u8]) -> Option<HandshakeContextRfc9000>;
    fn initial_context(&self, id: &[u8]) -> Option<InitialContextRfc9000>;

    fn insert_initial_context(&mut self, c: InitialContextRfc9000);
}
