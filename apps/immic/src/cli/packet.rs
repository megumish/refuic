use clap::{Parser, Subcommand};
use tracing::instrument;

use crate::error::Error;

mod parse;

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq, Clone)]
pub enum Commands {
    /// parse packet
    Parse(parse::Cli),
}

impl Commands {
    #[instrument(skip(self), name = "packet command", level = "trace")]
    pub fn run(self) -> Result<(), Error> {
        match self {
            Commands::Parse(cli) => cli.parse_stdin_packet(),
        }
    }
}
