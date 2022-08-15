use clap::{Parser, Subcommand};
use tracing::instrument;

use crate::error::Error;

mod packet;
mod var_int;

#[derive(Parser, Debug, PartialEq, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq, Clone)]
pub enum Commands {
    /// parsing packets
    Packet(packet::Cli),
    VarInt(var_int::Cli),
}

impl Commands {
    #[instrument(skip(self), name = "first command", level = "trace")]
    pub fn run(self) -> Result<(), Error> {
        match self {
            Commands::Packet(cli) => cli.command.run(),
            Commands::VarInt(cli) => cli.run(),
        }
    }
}
