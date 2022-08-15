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

pub fn crypto_data(frames: &Vec<super::Frame>) -> Result<Vec<u8>, CryptoDataError> {
    let mut crypto_frames = frames
        .iter()
        .filter_map(|f| match f {
            super::Frame::Crypto(c) => Some(c),
            _ => None,
        })
        .collect::<Vec<&Frame>>();
    crypto_frames.sort_by(|a, b| a.offset.cmp(&b.offset));
    let mut crypto_data = Vec::new();
    let mut current_offset = 0;
    for crypto_frame in crypto_frames {
        if current_offset != crypto_frame.offset {
            return Err(CryptoDataError::OffsetError {
                expected: current_offset,
                found: crypto_frame.offset,
            });
        }
        let data = &crypto_frame.crypto_data;
        crypto_data.extend(data);
        current_offset += data.len();
    }

    Ok(crypto_data)
}

#[derive(thiserror::Error, Debug)]
pub enum CryptoDataError {
    #[error("offset error")]
    OffsetError { expected: usize, found: usize },
}
