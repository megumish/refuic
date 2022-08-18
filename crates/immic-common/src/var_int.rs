use std::io::{Cursor, Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt};

#[derive(Debug, PartialEq, Clone)]
pub struct VarInt(u64);

impl VarInt {
    pub fn u64(&self) -> u64 {
        if self.0 - (0b00 << 6) < (1 << 6) {
            self.0 - (0b00 << 6)
        } else if self.0 - (0b01 << 14) < (1 << 14) {
            self.0 - (0b01 << 14)
        } else if self.0 - (0b10 << 30) < (1 << 30) {
            self.0 - (0b10 << 30)
        } else if self.0 - (0b11 << 62) < (1 << 62) {
            self.0 - (0b11 << 62)
        } else {
            panic!("unsupported size");
        }
    }

    pub fn len(&self) -> usize {
        if self.0 - (0b00 << 6) < (1 << 6) {
            1
        } else if self.0 - (0b01 << 14) < (1 << 14) {
            2
        } else if self.0 - (0b10 << 30) < (1 << 30) {
            4
        } else if self.0 - (0b11 << 62) < (1 << 62) {
            8
        } else {
            panic!("unsupported size");
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        if self.0 - (0b00 << 6) < (1 << 6) {
            vec![self.0 as u8]
        } else if self.0 - (0b01 << 14) < (1 << 14) {
            (self.0 as u16).to_be_bytes().to_vec()
        } else if self.0 - (0b10 << 30) < (1 << 30) {
            (self.0 as u32).to_be_bytes().to_vec()
        } else if self.0 - (0b11 << 62) < (1 << 62) {
            (self.0 as u64).to_be_bytes().to_vec()
        } else {
            panic!("unsupported size");
        }
    }

    pub fn try_new(u: u64) -> Result<Self, NewVarIntError> {
        Ok(if u < (1 << 6) {
            Self(u)
        } else if u < (1 << 14) {
            Self((0b01 << 14) + u)
        } else if u < (1 << 30) {
            Self((0b10 << 30) + u)
        } else if u < (1 << 62) {
            Self((0b11 << 62) + u)
        } else {
            return Err(NewVarIntError::UnsupportedSize);
        })
    }
}

pub trait ReadVarInt: Read {
    fn read_var_int(&mut self) -> Result<VarInt, std::io::Error> {
        let first_byte = self.read_u8()?;
        let length: usize = 1 << (first_byte >> 6);

        let mut buf = vec![0; length - 1];
        self.read_exact(&mut buf)?;
        let mut cursor = Cursor::new([&[first_byte], &buf[..]].concat());
        Ok(match length {
            1 => VarInt(first_byte as u64),
            2 => VarInt(cursor.read_u16::<NetworkEndian>()? as u64),
            4 => VarInt(cursor.read_u32::<NetworkEndian>()? as u64),
            8 => VarInt(cursor.read_u64::<NetworkEndian>()? as u64),
            _ => unreachable!("unexpected length"),
        })
    }
}

impl<T> ReadVarInt for T where T: Read {}

pub trait WriteVarInt: Write {
    fn write_var_int(&mut self, var_int: VarInt) -> Result<usize, std::io::Error> {
        let buf = var_int.to_vec();
        self.write(&buf)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NewVarIntError {
    #[error("unsupported size")]
    UnsupportedSize,
}
