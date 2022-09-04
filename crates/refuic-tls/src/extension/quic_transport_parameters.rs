use std::io::{Cursor, Read};

use refuic_common::{var_int::VarInt, ReadVarInt};

use super::ReadExtensionsError;

#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    parameters: Vec<TransportParameter>,
    length: usize,
}

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

impl Extension {
    pub fn len(&self) -> usize {
        self.length
    }

    pub fn parameters(&self) -> &Vec<TransportParameter> {
        &self.parameters
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [
            &(self.length as u16).to_be_bytes()[..],
            &self
                .parameters
                .iter()
                .flat_map(|parameter| match parameter {
                    TransportParameter::OriginalDestinationConnectionId(id) => {
                        let parameter_id = VarInt::try_new(0x00).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(id.len() as u64).unwrap().to_vec();
                        [&parameter_id, &parameter_length, &id[..]].concat()
                    }
                    TransportParameter::MaxIdleTimeout(timeout) => {
                        let parameter_id = VarInt::try_new(0x01).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*timeout).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::StateLessResetToken(token) => {
                        let parameter_id = VarInt::try_new(0x02).unwrap().to_vec();
                        let parameter_length =
                            VarInt::try_new(token.len() as u64).unwrap().to_vec();
                        [&parameter_id, &parameter_length, &token[..]].concat()
                    }
                    TransportParameter::MaxUdpPayloadSize(size) => {
                        let parameter_id = VarInt::try_new(0x03).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*size as u64).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::InitialMaxData(size) => {
                        let parameter_id = VarInt::try_new(0x04).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*size as u64).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::InitialMaxStreamDataBidirectionalLocal(size) => {
                        let parameter_id = VarInt::try_new(0x05).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*size as u64).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::InitialMaxStreamDataBidirectionalRemote(size) => {
                        let parameter_id = VarInt::try_new(0x06).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*size as u64).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::InitialMaxStreamDataUnidirectional(size) => {
                        let parameter_id = VarInt::try_new(0x07).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*size as u64).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::InitialMaxStreamsBidirectional(size) => {
                        let parameter_id = VarInt::try_new(0x08).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*size as u64).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::InitialMaxStreamsUnidirectoinal(size) => {
                        let parameter_id = VarInt::try_new(0x09).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*size as u64).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::AckDelayExponent(exp) => {
                        let parameter_id = VarInt::try_new(0x0a).unwrap().to_vec();
                        let parameter_bytes = match exp {
                            Some(e) => [*e],
                            None => [20u8],
                        };
                        let parameter_length = VarInt::try_new(parameter_bytes.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_bytes[..]].concat()
                    }
                    TransportParameter::MaxAckDelay(delay) => {
                        let parameter_id = VarInt::try_new(0x0b).unwrap().to_vec();
                        let parameter_bytes = VarInt::try_new(match delay {
                            Some(e) => *e,
                            None => ((2 << 14 - 1) as u16),
                        } as u64)
                        .unwrap()
                        .to_vec();
                        let parameter_length = VarInt::try_new(parameter_bytes.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_bytes[..]].concat()
                    }
                    TransportParameter::DisableActiveMigration => {
                        let parameter_id = VarInt::try_new(0x0c).unwrap().to_vec();
                        let parameter_bytes = [0u8; 0];
                        let parameter_length = VarInt::try_new(parameter_bytes.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_bytes[..]].concat()
                    }
                    TransportParameter::ActiveConnectionIdLimit(size) => {
                        let parameter_id = VarInt::try_new(0x0e).unwrap().to_vec();
                        let parameter_vec = VarInt::try_new(*size as u64).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(parameter_vec.len() as u64)
                            .unwrap()
                            .to_vec();
                        [&parameter_id, &parameter_length, &parameter_vec[..]].concat()
                    }
                    TransportParameter::InitialSourceConnectionId(id) => {
                        let parameter_id = VarInt::try_new(0x0f).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(id.len() as u64).unwrap().to_vec();
                        [&parameter_id, &parameter_length, &id[..]].concat()
                    }
                    TransportParameter::RetrySourceConnectionId(id) => {
                        let parameter_id = VarInt::try_new(0x10).unwrap().to_vec();
                        let parameter_length = VarInt::try_new(id.len() as u64).unwrap().to_vec();
                        [&parameter_id, &parameter_length, &id[..]].concat()
                    }
                    TransportParameter::Others(id, bytes) => {
                        let parameter_id = VarInt::try_new(*id).unwrap().to_vec();
                        let parameter_length =
                            VarInt::try_new(bytes.len() as u64).unwrap().to_vec();
                        [&parameter_id, &parameter_length, &bytes[..]].concat()
                    }
                })
                .collect::<Vec<u8>>(),
        ]
        .concat()
    }
}

pub fn parse_from_bytes(bytes: &[u8]) -> Result<super::Extension, ReadExtensionsError> {
    let length = bytes.len();
    let mut sum_of_length = 0;
    let mut input = Cursor::new(bytes);
    let mut parameters = Vec::new();
    while sum_of_length < length {
        let parameter_id = input.read_var_int()?;
        let parameter_length = input.read_var_int()?;
        let mut buf = vec![0; parameter_length.u64() as usize];
        input.read_exact(&mut buf)?;
        let parameter_var_int_num = {
            let mut temp_input = Cursor::new(&buf);
            temp_input.read_var_int().unwrap_or(VarInt::MAX)
        };
        parameters.push(match parameter_id.u64() {
            0x00 => TransportParameter::OriginalDestinationConnectionId(buf),
            0x01 => TransportParameter::MaxIdleTimeout(parameter_var_int_num.u64()),
            0x02 => TransportParameter::StateLessResetToken(buf),
            0x03 => TransportParameter::MaxUdpPayloadSize(parameter_var_int_num.u64() as usize),
            0x04 => TransportParameter::InitialMaxData(parameter_var_int_num.u64() as usize),
            0x05 => TransportParameter::InitialMaxStreamDataBidirectionalLocal(
                parameter_var_int_num.u64() as usize,
            ),
            0x06 => TransportParameter::InitialMaxStreamDataBidirectionalRemote(
                parameter_var_int_num.u64() as usize,
            ),
            0x07 => TransportParameter::InitialMaxStreamDataUnidirectional(
                parameter_var_int_num.u64() as usize,
            ),
            0x08 => TransportParameter::InitialMaxStreamsBidirectional(
                parameter_var_int_num.u64() as usize
            ),
            0x09 => TransportParameter::InitialMaxStreamsUnidirectoinal(
                parameter_var_int_num.u64() as usize,
            ),
            0x0a => TransportParameter::AckDelayExponent(if parameter_var_int_num.u64() > 20 {
                None
            } else {
                Some(parameter_var_int_num.u64() as u8)
            }),
            0x0b => TransportParameter::MaxAckDelay(if parameter_var_int_num.u64() > (1 << 14) {
                None
            } else {
                Some(parameter_var_int_num.u64() as u16)
            }),
            0x0c => TransportParameter::DisableActiveMigration,
            0x0e => {
                TransportParameter::ActiveConnectionIdLimit(parameter_var_int_num.u64() as usize)
            }
            0x0f => TransportParameter::InitialSourceConnectionId(buf),
            0x10 => TransportParameter::RetrySourceConnectionId(buf),
            x => TransportParameter::Others(x, buf),
        });
        sum_of_length +=
            parameter_id.len() + parameter_length.len() + parameter_length.u64() as usize
    }
    Ok(super::Extension::QuicTransportParameters(Extension {
        parameters,
        length,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use refuic_common::EndpointType;

    use crate::extension::{
        quic_transport_parameters::TransportParameter, read_extension, Extension,
    };

    #[test]
    fn read_extension_quic_tranport_parameters() -> Result<(), anyhow::Error> {
        let bytes =
            include_bytes!("./test_data/xargs_org/client_initial_0/quic_transport_parameters.bin");
        let mut input = Cursor::new(&bytes[..]);
        let extension = read_extension(&mut input, &EndpointType::Client)?;
        assert_eq!(
            extension,
            Extension::QuicTransportParameters(super::Extension {
                parameters: vec![
                    TransportParameter::MaxUdpPayloadSize(65527),
                    TransportParameter::InitialMaxData(10485760),
                    TransportParameter::InitialMaxStreamDataBidirectionalLocal(1048576),
                    TransportParameter::InitialMaxStreamDataBidirectionalRemote(1048576),
                    TransportParameter::InitialMaxStreamDataUnidirectional(1048576),
                    TransportParameter::InitialMaxStreamsBidirectional(10),
                    TransportParameter::InitialMaxStreamsUnidirectoinal(10),
                    TransportParameter::AckDelayExponent(Some(3)),
                    TransportParameter::MaxAckDelay(Some(25)),
                    TransportParameter::InitialSourceConnectionId(b"c_cid".to_vec())
                ],
                length: 49
            })
        );
        assert_eq!(extension.to_vec(), bytes);
        Ok(())
    }
}
