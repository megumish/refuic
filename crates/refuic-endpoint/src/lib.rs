use context::{initial::InitialContextRfc9000, ContextRfc9000};
use refuic_common::{endpoint_type, EndpointType, QuicVersion};
use refuic_packet::{
    long::{
        self,
        initial::{self, ServerInitialPacket, UnprotectError},
    },
    packet, LongHeaderPacket, PacketReadError, PacketTransformError,
};
use tokio::net::{ToSocketAddrs, UdpSocket};

mod context;
mod socket;

pub struct EndpointRfc9000<C>
where
    C: ContextRfc9000,
{
    context: C,
    socket: UdpSocket,
    endpoint_type: EndpointType,
}

impl<C> EndpointRfc9000<C>
where
    C: ContextRfc9000,
{
    async fn bind(
        addr: impl ToSocketAddrs,
        endpoint_type: EndpointType,
    ) -> Result<Self, BindError> {
        Ok(Self {
            context: ContextRfc9000::new(),
            socket: UdpSocket::bind(addr).await?,
            endpoint_type,
        })
    }

    // 受け取ったメッセージと相手のコネクションIDを返す
    async fn recv(&mut self) -> Result<(Vec<u8>, Vec<u8>), RecvError> {
        let mut buf = Vec::new();
        loop {
            buf.extend({
                // UDPデータグラムに入る最小のバイト数は1200であるので
                // バッファーもとりあえずは1200以上の値にしておく
                let mut buf = [0; 2048];
                let length = self.socket.recv(&mut buf).await?;
                buf[0..length].to_owned()
            });

            match long::parse_from_bytes(&buf, &QuicVersion::Rfc9000) {
                Err(long::ParseFromBytesError::PacketTransformError(
                    packet::PacketTransformError::NotLongPacket,
                )) => { /* do nothing */ }
                Err(long::ParseFromBytesError::PacketReadError(PacketReadError::StdIo(e))) => {
                    match e.kind() {
                        std::io::ErrorKind::UnexpectedEof => continue,
                        _ => return Err(e).map_err(Into::into),
                    }
                }
                Err(long::ParseFromBytesError::PacketTransformError(
                    PacketTransformError::StdIo(e),
                )) => match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => continue,
                    _ => return Err(e).map_err(Into::into),
                },
                Err(e) => return Err(e).map_err(Into::into),
                Ok(p) => {
                    let handshake_context = self
                        .context
                        .handshake_context(p.destination_connection_id());
                    if let Some(handshake_context) = handshake_context {
                        if handshake_context.after_done() {
                            unimplemented!("reach after handshake world!")
                        }
                    }

                    // TODO: メッセージ長が足りなかった場合、さらに読み込む
                    let message_length = self.handshake(p)?;
                    // message_lengthは必ずbuf以上の長さになるはずなので
                    // message_lengthがbufより大きい場合と
                    // それ以外（=message_lengthと同じ）場合だけを考えれば十分
                    if buf.len() > message_length {
                        buf = buf[message_length..].to_vec();
                    } else {
                        buf = Vec::new();
                    }
                    continue;
                }
            }

            unimplemented!("reach short message!")
        }
        Ok((Vec::new(), Vec::new()))
    }

    fn handshake(&mut self, long: LongHeaderPacket) -> Result<usize, HandshakeError> {
        let initial_context = self
            .context
            .initial_context(long.destination_connection_id());
        if let Some(initial_context) = initial_context {
            if initial_context.after_hello() {
                unimplemented!();
            }
            unimplemented!("initial_contextを更新する");
        }

        match self.endpoint_type {
            EndpointType::Server => {
                match initial::ClientInitialPacket::unprotect(
                    &long,
                    &long.destination_connection_id(),
                    &QuicVersion::Rfc9000,
                    &EndpointType::Server,
                ) {
                    Ok(p) => {
                        // initial_contextが無いので作成して処理を進める
                        let initial_context = InitialContextRfc9000::from_client_initial(&p);
                        self.context.insert_initial_context(initial_context);
                        let server_hello_initial = ServerInitialPacket::hello();
                    }
                    Err(UnprotectError::NotInitialPacket) => { /* 他のパケットのパースへと処理を進める */
                    }
                    Err(e) => return Err(e).map_err(Into::into),
                };
            }
            EndpointType::Client => {
                // initial_contextがない状態はInitial Packetを一度も送ってない状況だと仮定して
                // 後続のInitial Packetも送られてこないはずなので、他のパケットのパースへと処理を進める
            }
        }
        Ok(0)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BindError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum RecvError {
    #[error("std I/O error")]
    StdIoError(#[from] std::io::Error),
    #[error("parse long packet from bytes")]
    LongPacketFromBytesError(#[from] long::ParseFromBytesError),
    #[error("handshake error")]
    HandshakeError(#[from] HandshakeError),
}

#[derive(thiserror::Error, Debug)]
pub enum HandshakeError {
    #[error("unprotect error")]
    UnprotectError(#[from] UnprotectError),
}
