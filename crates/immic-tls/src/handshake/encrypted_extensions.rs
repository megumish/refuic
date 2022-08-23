use crate::extension::Extension;

pub struct EncryptedExtensions {
    extensions: Vec<Extension>,
}

impl EncryptedExtensions {
    pub fn new() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let extensions_bytes = self
            .extensions
            .iter()
            .map(Extension::to_vec)
            .flatten()
            .collect::<Vec<u8>>();
        buf.extend((extensions_bytes.len() as u16).to_be_bytes());
        buf.extend(extensions_bytes);
        buf
    }
}
