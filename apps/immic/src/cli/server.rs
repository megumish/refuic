use std::net::UdpSocket;

use clap::Parser;
use ed25519_dalek::Keypair;
use immic_common::{EndpointType, QuicVersion};
use immic_frame::frame;
use immic_packet::long;
use rand::{rngs::StdRng, SeedableRng};

use crate::error::Error;

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Cli {
    #[clap(value_parser)]
    address: String,
}

impl Cli {
    pub fn run(self) -> Result<(), Error> {
        let socket = UdpSocket::bind(self.address)?;

        {
            let mut buf = vec![0; 1200];
            let (_, peer_addr) = socket.recv_from(&mut buf)?;

            // https://www.rfc-editor.org/rfc/rfc9000.html#name-example-handshake-flows

            let (server_initial, _keypair) = {
                let initial = long::initial::parse_from_bytes(
                    &buf,
                    &QuicVersion::Rfc9000,
                    &EndpointType::Server,
                )?;
                let frames = frame::parse_from_bytes(initial.payload(), &QuicVersion::Rfc9000)?;
                let crypto_data = frame::crypto::crypto_data(&frames)?;
                let client_hello_data =
                    immic_tls::handshake::client_hello::parse_from_bytes(&crypto_data)?;
                let mut random_generator = StdRng::from_entropy();
                let keypair: Keypair = Keypair::generate(&mut random_generator);
                (
                    initial
                        .server_initial(&client_hello_data, keypair.public.as_bytes())
                        .protect(&EndpointType::Server)?,
                    keypair.secret,
                )
            };

            {
                let buf = server_initial.to_bytes();
                let _ = socket.send_to(&buf, peer_addr);
            }
        }
        Ok(())
    }
}
