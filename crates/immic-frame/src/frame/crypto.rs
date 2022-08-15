use std::io::{Cursor, Read};

use immic_common::ReadVarInt;

use super::ParseFrameError;

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    offset: usize,
    crypto_data: Vec<u8>,
}

pub fn read_crypto_frame(input: &mut Cursor<&[u8]>) -> Result<Frame, ParseFrameError> {
    let offset = input.read_var_int()?.u64() as usize;
    let crypto_data_length = input.read_var_int()?.u64() as usize;
    let mut crypto_data = vec![0; crypto_data_length];
    let _ = input.read_exact(&mut crypto_data)?;
    Ok(Frame {
        offset,
        crypto_data,
    })
}
