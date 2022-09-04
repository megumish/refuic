use std::io::{Cursor, Read};

use refuic_common::{var_int::VarInt, ReadVarInt};

use super::ParseFrameError;

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    offset: usize,
    crypto_data: Vec<u8>,
}

impl Frame {
    pub fn new(crypto_data: Vec<u8>) -> super::FrameRfc9000 {
        super::FrameRfc9000::Crypto(Self {
            offset: 0,
            crypto_data,
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let offset = VarInt::try_new(self.offset as u64).unwrap();
        let crypto_data_length = VarInt::try_new(self.crypto_data.len() as u64).unwrap();
        [
            offset.to_vec(),
            crypto_data_length.to_vec(),
            self.crypto_data.clone(),
        ]
        .concat()
    }

    pub fn vec_len(&self) -> usize {
        VarInt::try_new(self.offset as u64).unwrap().len()
            + VarInt::try_new(self.crypto_data.len() as u64)
                .unwrap()
                .len()
            + self.crypto_data.len()
    }

    pub fn crypto_data(&self) -> &Vec<u8> {
        &self.crypto_data
    }
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

pub fn crypto_data(frames: &Vec<super::FrameRfc9000>) -> Result<Vec<u8>, CryptoDataError> {
    let mut crypto_frames = frames
        .iter()
        .filter_map(|f| match f {
            super::FrameRfc9000::Crypto(c) => Some(c),
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
