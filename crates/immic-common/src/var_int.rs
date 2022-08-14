use std::io::{Cursor, Read};

use byteorder::{NetworkEndian, ReadBytesExt};

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

pub enum ParseError {
    UnexpectedEnd(usize),
}
