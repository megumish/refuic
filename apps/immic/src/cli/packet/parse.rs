use std::io::Read;

use clap::Parser;
use immic_common::QuicVersion;
use immic_packet::{long, packet, LongHeaderPacket, Packet};
use tracing::{info, instrument};

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Cli {}

impl Cli {
    #[instrument(skip(self), name = "parse packet from stdin", level = "info")]
    pub fn parse_stdin_packet(&self) -> Result<(), crate::error::Error> {
        let mut stdin = std::io::stdin();

        let mut buf = Vec::new();

        let _ = stdin.read_to_end(&mut buf)?;

        info!("read from stdin: {:?}", buf);

        let packet: Packet = packet::parse_from_bytes(buf)?;

        info!("input bytes into Packet format: {:?}", packet);

        let long: LongHeaderPacket = long::parse_from_packet(packet, QuicVersion::Rfc9000)?;

        info!("packet into Long Header Packet format: {:?}", long);

        Ok(())
    }
}
