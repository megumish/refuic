use clap::{Parser, Subcommand};

mod init_key_iv_hp;

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug, PartialEq, Clone)]
pub enum Command {
    KeyIvHp(init_key_iv_hp::Cli),
}

impl Cli {
    pub fn run(&self) -> Result<(), anyhow::Error> {
        match &self.command {
            Command::KeyIvHp(cli) => cli.run(),
        }
    }
}
