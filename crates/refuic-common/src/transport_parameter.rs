#[derive(Debug, PartialEq, Clone)]
pub enum TransportParameter {
    OriginalDestinationConnectionId(Vec<u8>),
    // 8バイト以上だったら、u64::MAXをとるようにする
    MaxIdleTimeout(u64),
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.6.1
    // This parameter is a sequence of 16 bytes
    StateLessResetToken(Vec<u8>),
    MaxUdpPayloadSize(usize),
    InitialMaxData(usize),
    InitialMaxStreamDataBidirectionalLocal(usize),
    InitialMaxStreamDataBidirectionalRemote(usize),
    InitialMaxStreamDataUnidirectional(usize),
    InitialMaxStreamsBidirectional(usize),
    InitialMaxStreamsUnidirectoinal(usize),
    // Values above 20 are invalid.
    // invalid なときはNoneにする
    AckDelayExponent(Option<u8>),
    // Values of 214 or greater are invalid.
    // invalid なときはNoneにする
    MaxAckDelay(Option<u16>),
    // This parameter is a zero-length value.
    DisableActiveMigration,
    // 面倒くさいので省略する
    // PreferredAddress,
    // 最低2以上の値をとること
    ActiveConnectionIdLimit(usize),
    InitialSourceConnectionId(Vec<u8>),
    RetrySourceConnectionId(Vec<u8>),
    Others(u64, Vec<u8>),
}
