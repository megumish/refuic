use std::net::UdpSocket;

use clap::Parser;
use immic_common::{EndpointType, QuicVersion};
use immic_packet::long;

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

            let server_initial = {
                let initial = long::initial::parse_from_bytes(
                    &buf,
                    &QuicVersion::Rfc9000,
                    &EndpointType::Server,
                )?;
                initial.server_initial().protect(&EndpointType::Server)?
            };

            {
                let buf = server_initial.to_bytes();
                let _ = socket.send_to(&buf, peer_addr);
            }
        }
        Ok(())
    }
}
