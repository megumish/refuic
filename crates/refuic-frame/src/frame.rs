use std::io::Cursor;

use refuic_common::{var_int::VarInt, ReadVarInt};

use self::crypto::read_crypto_frame;

pub mod ack;
pub mod connection_close;
pub mod crypto;
pub mod data_blocked;
pub mod max_data;
pub mod max_stream_data;
pub mod max_streams;
pub mod new_connection_id;
pub mod new_token;
pub mod path_challenge;
pub mod path_response;
pub mod reset_stream;
pub mod retire_connection_id;
pub mod stop_sending;
pub mod stream;
pub mod stream_data_blocked;
pub mod streams_blocked;

#[derive(Debug, PartialEq, Clone)]
pub enum FrameRfc9000 {
    Padding,
    Ping,
    Ack(ack::Frame),
    ResetStream(reset_stream::Frame),
    StopSending(stop_sending::Frame),
    Crypto(crypto::Frame),
    NewToken(new_token::Frame),
    Stream(stream::Frame),
    MaxData(max_data::Frame),
    MaxStreamData(max_stream_data::Frame),
    MaxStreams(max_streams::Frame),
    DataBlocked(data_blocked::Frame),
    StreamDataBlocked(stream_data_blocked::Frame),
    StreamsBlocked(streams_blocked::Frame),
    NewConnectionID(new_connection_id::Frame),
    RetireConnectionID(retire_connection_id::Frame),
    PathChallenge(path_challenge::Frame),
    PathResponse(path_response::Frame),
    ConnectionClose(connection_close::Frame),
    HandshakeDone,
    Extension(u64),
}

impl FrameRfc9000 {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Padding => vec![0x00],
            Self::Ping => vec![0x01],
            Self::Crypto(f) => {
                let frame_type = VarInt::try_new(6).unwrap();
                [frame_type.to_vec(), f.to_vec()].concat()
            }
            Self::Ack(f) => {
                let frame_type = f.frame_type();
                [frame_type.to_vec(), f.to_vec()].concat()
            }
            _ => unimplemented!(),
        }
    }

    pub fn vec_len(&self) -> usize {
        match self {
            Self::Padding => 1,
            Self::Ping => 1,
            Self::Crypto(f) => {
                let frame_type = VarInt::try_new(6).unwrap();
                frame_type.len() + f.vec_len()
            }
            Self::Ack(f) => {
                let frame_type = f.frame_type();
                frame_type.len() + f.vec_len()
            }
            _ => unimplemented!(),
        }
    }
}

pub fn parse_from_bytes_v1(bytes: &[u8]) -> Result<Vec<FrameRfc9000>, ParseFrameError> {
    let length = bytes.len();
    let mut input = Cursor::new(bytes);
    let mut frames = Vec::new();
    let mut sum_of_length = 0usize;
    while sum_of_length < length {
        let frame_type = input.read_var_int()?;
        let frame = match frame_type.u64() {
            0 => FrameRfc9000::Padding,
            1 => FrameRfc9000::Ping,
            6 => FrameRfc9000::Crypto(read_crypto_frame(&mut input)?),
            _ => unimplemented!(),
        };
        sum_of_length += frame_type.len() + frame.vec_len();
        frames.push(frame);
    }
    Ok(frames)
}

#[derive(thiserror::Error, Debug)]
pub enum ParseFrameError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}
