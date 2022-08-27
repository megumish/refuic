use std::io::Read;

use clap::Parser;
use refuic_common::{EndpointType, QuicVersion};
use refuic_frame::frame::{self, Frame};
use refuic_packet::{
    long::{self, initial::ClientInitialPacket},
    packet, LongHeaderPacket, Packet,
};
use tracing::{info, instrument};

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Cli {}

impl Cli {
    #[instrument(skip(self), name = "parse packet from stdin", level = "info")]
    pub fn parse_stdin_packet(&self) -> Result<(), anyhow::Error> {
        let mut stdin = std::io::stdin();

        let mut buf = Vec::new();

        let _ = stdin.read_to_end(&mut buf)?;

        info!("read from stdin: {:?}", buf);

        let packet: Packet = packet::parse_from_bytes(&buf)?;

        info!("input bytes into Packet format: {:?}", packet);

        let long: LongHeaderPacket = long::parse_from_packet(packet, &QuicVersion::Rfc9000)?;

        info!("packet into Long Header Packet format: {:?}", long);

        let initial: ClientInitialPacket = ClientInitialPacket::unprotect(
            &long,
            None,
            &QuicVersion::Rfc9000,
            &EndpointType::Server,
        )?;

        info!("remove protection from long header packet: {:?}", initial);

        let frames: Vec<Frame> = frame::parse_from_bytes(initial.payload(), &QuicVersion::Rfc9000)?;

        info!("initial packet payload into frames: {:?}", frames);

        let crypto_data: Vec<u8> = frame::crypto::crypto_data(&frames)?;
        let client_hello_data =
            refuic_tls::handshake::client_hello::parse_from_bytes(&crypto_data)?;

        info!(
            "frames crypto data into tls handshake client hello data format: {:?}",
            client_hello_data
        );

        info!(
            "crypto data length: {:?}, actual total length: {:?}",
            crypto_data.len(),
            client_hello_data.total_length
        );

        Ok(())
    }
}
