mod cli;
mod error;

use clap::Parser;
use cli::Cli;
use error::Error;

fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();

    cli.command.run()
}
