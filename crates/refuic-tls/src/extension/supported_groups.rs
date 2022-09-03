use std::io::Cursor;

use byteorder::{NetworkEndian, ReadBytesExt};

use crate::named_curve::NamedCurve;

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    named_curves: Vec<NamedCurve>,
    length: usize,
}

impl Extension {
    pub fn len(&self) -> usize {
        2 + self.length
    }

    pub fn named_curves(&self) -> &Vec<NamedCurve> {
        &self.named_curves
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [
            &(self.length as u16).to_be_bytes()[..],
            &self
                .named_curves
                .iter()
                .flat_map(|nc| nc.to_bytes().to_vec())
                .collect::<Vec<u8>>(),
        ]
        .concat()
    }
}

pub fn parse_from_bytes(bytes: &[u8]) -> Result<super::Extension, ReadExtensionsError> {
    let mut input = Cursor::new(bytes);
    let (named_curves, length) = {
        let length = input.read_u16::<NetworkEndian>()? as usize;
        let mut curves = Vec::new();
        for _ in 0..length / 2 {
            let curve_type = input.read_u16::<NetworkEndian>()?;
            curves.push(NamedCurve::from_u16(curve_type));
        }
        (curves, length)
    };

    Ok(super::Extension::SupportedGroups(Extension {
        named_curves,
        length,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{
        extension::{read_extension, Extension},
        named_curve::NamedCurve,
    };

    #[test]
    fn read_extension_supported_groups() -> Result<(), anyhow::Error> {
        let bytes = include_bytes!("./test_data/xargs_org/client_initial_0/supported_groups.bin");
        let mut input = Cursor::new(&bytes[..]);
        let extension = read_extension(&mut input)?;
        assert_eq!(
            extension,
            Extension::SupportedGroups(super::Extension {
                named_curves: vec![
                    NamedCurve::X25519,
                    NamedCurve::Secp256r1,
                    NamedCurve::Secp384rl,
                ],
                length: 6,
            })
        );
        assert_eq!(extension.to_vec(), bytes);
        Ok(())
    }
}
