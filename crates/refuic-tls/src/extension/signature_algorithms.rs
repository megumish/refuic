use std::io::Cursor;

use byteorder::{NetworkEndian, ReadBytesExt};

use crate::signature_scheme::SignatureScheme;

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    signature_schemes: Vec<SignatureScheme>,
    length: usize,
}

impl Extension {
    pub fn len(&self) -> usize {
        2 + self.length
    }

    pub fn signature_schemes(&self) -> &Vec<SignatureScheme> {
        &self.signature_schemes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [
            &(self.length as u16).to_be_bytes()[..],
            &self
                .signature_schemes
                .iter()
                .flat_map(|ss| ss.to_bytes().to_vec())
                .collect::<Vec<u8>>(),
        ]
        .concat()
    }
}

pub fn parse_from_bytes(bytes: &[u8]) -> Result<super::Extension, ReadExtensionsError> {
    let mut input = Cursor::new(bytes);
    let (signature_schemes, length) = {
        let length = input.read_u16::<NetworkEndian>()? as usize;
        let mut schemes = Vec::new();
        for _ in 0..length / 2 {
            let scheme_type = input.read_u16::<NetworkEndian>()?;
            schemes.push(SignatureScheme::from_u16(scheme_type));
        }
        (schemes, length)
    };
    Ok(super::Extension::SignatureAlgorithms(Extension {
        signature_schemes,
        length,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{
        extension::{read_extension, Extension},
        signature_scheme::SignatureScheme,
    };

    #[test]
    fn read_extension_signature_alogrithms() -> Result<(), anyhow::Error> {
        let bytes =
            include_bytes!("./test_data/xargs_org/client_initial_0/signature_algorithms.bin");
        let mut input = Cursor::new(&bytes[..]);
        let extension = read_extension(&mut input)?;
        assert_eq!(
            extension,
            Extension::SignatureAlgorithms(super::Extension {
                signature_schemes: vec![
                    SignatureScheme::EcdsaSecp256r1Sha256,
                    SignatureScheme::RsaPssRsaeSha256,
                    SignatureScheme::RsaPkcs1Sha256,
                    SignatureScheme::EcdsaSecp384r1Sha384,
                    SignatureScheme::RsaPssRsaeSha384,
                    SignatureScheme::RsaPkcs1Sha384,
                    SignatureScheme::RsaPssRsaeSha512,
                    SignatureScheme::RsaPkcs1Sha512,
                    SignatureScheme::RsaPkcs1Sha1,
                ],
                length: 18,
            })
        );
        assert_eq!(extension.to_vec(), bytes);
        Ok(())
    }
}
