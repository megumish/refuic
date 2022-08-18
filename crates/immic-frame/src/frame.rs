use std::io::Cursor;

use immic_common::{var_int::VarInt, QuicVersion, ReadVarInt};

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
pub enum Frame {
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

impl Frame {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Crypto(f) => {
                let frame_type = VarInt::try_new(6).unwrap();
                [frame_type.to_vec(), f.to_vec()].concat()
            }
            _ => unimplemented!(),
        }
    }
}

pub fn parse_from_bytes(
    bytes: &[u8],
    version: &QuicVersion,
) -> Result<Vec<Frame>, ParseFrameError> {
    match version {
        QuicVersion::Rfc9000 => parse_from_bytes_v1(bytes),
        _ => unimplemented!("no supported version"),
    }
}

pub fn parse_from_bytes_v1(bytes: &[u8]) -> Result<Vec<Frame>, ParseFrameError> {
    let mut input = Cursor::new(bytes);
    let mut frames = Vec::new();
    loop {
        let frame_type = match input.read_var_int() {
            Err(err) => match err.kind() {
                std::io::ErrorKind::UnexpectedEof => return Ok(frames),
                _ => return Err(err).map_err(Into::into),
            },
            Ok(x) => x,
        };
        let frame = match frame_type.u64() {
            6 => Frame::Crypto(read_crypto_frame(&mut input)?),
            _ => unimplemented!(),
        };
        frames.push(frame);
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseFrameError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}
