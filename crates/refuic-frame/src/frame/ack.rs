use refuic_common::var_int::VarInt;

#[derive(Debug, PartialEq, Clone)]
pub struct Frame {
    largest_acknowledged: u32,
    ack_delay: VarInt,
    first_ack_range: VarInt,
    ack_range: Vec<AckRange>,
    ecn_counts: Option<EcnCounts>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct AckRange {
    gap: VarInt,
    ack_range_length: VarInt,
}

#[derive(Debug, PartialEq, Clone)]
pub struct EcnCounts {
    ect0_count: VarInt,
    ect1_count: VarInt,
    ecn_ce_count: VarInt,
}

impl Frame {
    pub fn new(packet_number: u32) -> super::FrameRfc9000 {
        let largest_acknowledged = packet_number;
        // ok
        let ack_delay = VarInt::try_new(1 << 6).unwrap();
        // ok because u32 < u64
        let first_ack_range =
            VarInt::try_new(packet_number.checked_sub(1).unwrap_or(0) as u64).unwrap();
        let ack_range = Vec::new();
        let ecn_counts = None;
        super::FrameRfc9000::Ack(Frame {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ack_range,
            ecn_counts,
        })
    }

    pub fn frame_type(&self) -> VarInt {
        VarInt::try_new(match self.ecn_counts {
            None => 0x02,
            Some(_) => 0x03,
        })
        .unwrap()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(
            VarInt::try_new(self.largest_acknowledged as u64)
                .unwrap()
                .to_vec(),
        );
        buf.extend(self.ack_delay.to_vec());
        buf.extend(
            VarInt::try_new(self.ack_range.len() as u64)
                .unwrap()
                .to_vec(),
        );
        buf.extend(self.first_ack_range.to_vec());
        buf.extend(self.ack_range.iter().map(AckRange::to_vec).flatten());
        match &self.ecn_counts {
            Some(c) => buf.extend(c.to_vec()),
            None => { /* do nothing */ }
        }
        buf
    }
}

impl AckRange {
    pub fn to_vec(&self) -> Vec<u8> {
        [self.gap.to_vec(), self.ack_range_length.to_vec()].concat()
    }
}

impl EcnCounts {
    pub fn to_vec(&self) -> Vec<u8> {
        [
            self.ect0_count.to_vec(),
            self.ect1_count.to_vec(),
            self.ecn_ce_count.to_vec(),
        ]
        .concat()
    }
}
