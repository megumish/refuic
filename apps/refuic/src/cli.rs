use clap::{Parser, Subcommand};
use tracing::instrument;

mod server;
mod var_int;

#[derive(Parser, Debug, PartialEq, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq, Clone)]
pub enum Commands {
    Server(server::Cli),
    VarInt(var_int::Cli),
}

impl Commands {
    #[instrument(skip(self), name = "first command", level = "trace")]
    pub fn run(self) -> Result<(), anyhow::Error> {
        match self {
            Commands::VarInt(cli) => cli.run(),
            Commands::Server(cli) => cli.run(),
        }
    }
}
