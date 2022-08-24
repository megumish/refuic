//! # refuic は QUIC を実装するときに参考になるように書かれたQUICのRust実装です。
mod cli;
mod error;

use clap::Parser;
use cli::Cli;
use error::Error;

pub fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();

    cli.command.run()
}
