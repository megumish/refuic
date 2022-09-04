#[derive(Debug, PartialEq, Clone)]
pub struct PacketNumber(u32);

impl PacketNumber {
    pub fn new() -> Self {
        PacketNumber(0)
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        if self.0 < (1 << 8) {
            (self.0 as u8).to_be_bytes().to_vec()
        } else if self.0 < (1 << 16) {
            (self.0 as u16).to_be_bytes().to_vec()
        } else if self.0 < (1 << 24) {
            self.0.to_be_bytes()[1..].to_vec()
        } else {
            self.0.to_be_bytes().to_vec()
        }
    }

    pub(crate) fn vec_len(&self) -> usize {
        if self.0 < (1 << 8) {
            1
        } else if self.0 < (1 << 16) {
            2
        } else if self.0 < (1 << 24) {
            3
        } else {
            4
        }
    }

    pub(crate) const fn max_vec_len() -> usize {
        4
    }

    pub(crate) fn try_from_bytes(b: &[u8]) -> Result<Self, FromBytesError> {
        if b.is_empty() {
            return Err(FromBytesError);
        }
        Ok(if b.len() == 1 {
            PacketNumber(b[0] as u32)
        } else if b.len() == 2 {
            PacketNumber(u16::from_be_bytes([b[0], b[1]]) as u32)
        } else if b.len() == 3 {
            PacketNumber(u32::from_be_bytes([0, b[0], b[1], b[2]]))
        } else {
            PacketNumber(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        })
    }

    pub(crate) fn from_u32(u: u32) -> Self {
        PacketNumber(u)
    }

    pub(crate) fn u32(&self) -> u32 {
        self.0
    }

    pub fn next(&self) -> Self {
        PacketNumber(self.0 + 1)
    }
}

#[derive(thiserror::Error, Debug)]
#[error("from bytes error")]
pub(crate) struct FromBytesError;

#[cfg(test)]
mod tests {
    use super::PacketNumber;

    #[test]
    fn u8_to_vec() {
        let pn = PacketNumber(u8::MAX as u32);

        let pn_vec = pn.to_vec();
        assert_eq!(pn_vec, vec![u8::MAX]);
    }

    #[test]
    fn u16_to_vec() {
        let pn = PacketNumber(u16::MAX as u32);

        let pn_vec = pn.to_vec();
        assert_eq!(pn_vec, vec![u8::MAX; 2]);
    }

    #[test]
    fn u24_to_vec() {
        let pn = PacketNumber((u16::MAX) as u32 + 1);

        let pn_vec = pn.to_vec();
        assert_eq!(pn_vec, vec![1, 0, 0]);
    }

    #[test]
    fn u32_to_vec() {
        let pn = PacketNumber(u32::MAX);

        let pn_vec = pn.to_vec();
        assert_eq!(pn_vec, vec![u8::MAX; 4]);
    }
}
