use std::io::Cursor;

use byteorder::ReadBytesExt;

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    modes: Vec<PskKeyExchangeMode>,
    length: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum PskKeyExchangeMode {
    PskKey,
    PskKeyWithDhe,
    Others(u8),
}

impl PskKeyExchangeMode {
    fn u8(&self) -> u8 {
        match self {
            Self::PskKey => 0,
            Self::PskKeyWithDhe => 1,
            Self::Others(x) => *x,
        }
    }
}

impl Extension {
    pub fn len(&self) -> usize {
        1 + self.length
    }

    pub fn modes(&self) -> &Vec<PskKeyExchangeMode> {
        &self.modes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [
            &(self.length as u8).to_be_bytes()[..],
            &self
                .modes
                .iter()
                .map(PskKeyExchangeMode::u8)
                .collect::<Vec<u8>>(),
        ]
        .concat()
    }
}

pub fn parse_from_bytes(bytes: &[u8]) -> Result<super::Extension, ReadExtensionsError> {
    let mut input = Cursor::new(bytes);
    let (modes, length) = {
        let length = input.read_u8()? as usize;
        let mut modes = Vec::new();
        for _ in 0..length {
            let mode_num = input.read_u8()?;
            let mode = match mode_num {
                0 => PskKeyExchangeMode::PskKey,
                1 => PskKeyExchangeMode::PskKeyWithDhe,
                x => PskKeyExchangeMode::Others(x),
            };
            modes.push(mode);
        }
        (modes, length)
    };
    Ok(super::Extension::PskKeyExchangeModes(Extension {
        modes,
        length,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use refuic_common::EndpointType;

    use crate::extension::{psk_key_exchange_modes::PskKeyExchangeMode, read_extension, Extension};

    #[test]
    fn read_extension_psk_key_exchange_modes() -> Result<(), anyhow::Error> {
        let bytes =
            include_bytes!("./test_data/xargs_org/client_initial_0/psk_key_exchange_modes.bin");
        let mut input = Cursor::new(&bytes[..]);
        let extension = read_extension(&mut input, &EndpointType::Client)?;
        assert_eq!(
            extension,
            Extension::PskKeyExchangeModes(super::Extension {
                modes: vec![PskKeyExchangeMode::PskKeyWithDhe],
                length: 1,
            })
        );
        assert_eq!(extension.to_vec(), bytes);
        Ok(())
    }
}
