use std::io::Read;

use clap::Parser;
use immic_packet::Packet;
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

        let packet: Packet = buf.try_into()?;

        info!("input bytes into Packet format: {:?}", packet);

        Ok(())
    }
}
