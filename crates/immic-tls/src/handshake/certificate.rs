use crate::extension::Extension;

pub struct Certificate {
    length: usize,
    request_context: Vec<u8>,
    entry: Vec<Entry>,
}

pub struct Entry {
    cert_data: Vec<u8>,
    extensions: Vec<Extension>,
}

impl Certificate {
    pub fn new() -> Self {
        Self {
            length: 0,
            request_context: Vec::new(),
            entry: Vec::new(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let message_type = 11u8;
        let length_bytes = {
            let mut buf = Vec::new();
            for i in 0..3usize {
                buf.push(((self.length >> (3 - (i + 1)) * 8) & 0xff) as u8)
            }
            buf
        };
        buf.push(message_type);
        buf.extend(length_bytes);
        buf.push(self.request_context.len() as u8);
        buf.extend(&self.request_context);
        buf.extend((self.entry.len() as u16).to_be_bytes());
        buf.extend(self.entry.iter().map(Entry::to_vec).flatten());
        buf
    }
}

impl Entry {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend((self.cert_data.len() as u16).to_be_bytes());
        buf.extend(&self.cert_data);
        buf.extend(self.extensions.iter().map(Extension::to_vec).flatten());
        buf
    }
}
