use std::io::Cursor;

use clap::Parser;
use refuic_common::ReadVarInt;

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Cli {
    #[clap(value_parser)]
    byte_list: String,
}

impl Cli {
    pub fn run(self) -> Result<(), anyhow::Error> {
        let bytes: Vec<u8> = serde_json::from_str(&self.byte_list)?;
        let mut input = Cursor::new(&bytes);
        let var_int = input.read_var_int()?;
        println!("{}", var_int.u64());
        Ok(())
    }
}
