use std::{net::SocketAddr, str::FromStr};

use refuic_common::EndpointType;
use refuic_packet::{packet_number::PacketNumber, LongHeaderPacket};
use refuic_tls::{cipher_suite::CipherSuite, named_curve::NamedCurve};

use crate::{
    connection::{
        ConnectionMap, ConnectionRfc9000, FetchConnectionError, NewConnectionError,
        UpdateConnectionError,
    },
    socket::{RecvError, Socket},
    Endpoint,
};

#[test]
fn not_initial_packet() -> Result<(), anyhow::Error> {
    struct ConnectionMapMock;
    struct SocketMock;

    impl ConnectionMap for ConnectionMapMock {
        fn new_connection_v1(
            &self,
            destination_connection_id: &[u8],
            socket: SocketAddr,
        ) -> Result<&ConnectionRfc9000, NewConnectionError> {
            todo!()
        }
        fn connection_v1(
            &self,
            destination_connection_id: &[u8],
        ) -> Result<Option<&ConnectionRfc9000>, FetchConnectionError> {
            todo!()
        }
        fn update_cipher_suites_v1(
            &self,
            destination_connection_id: &[u8],
            cipher_suites: &[CipherSuite],
        ) -> Result<(), UpdateConnectionError> {
            todo!()
        }
        fn insert_client_named_curves_v1(
            &self,
            destination_connection_id: &[u8],
            named_curves: &[NamedCurve],
        ) -> Result<(), UpdateConnectionError> {
            todo!()
        }
    }

    #[async_trait::async_trait]
    impl Socket for SocketMock {
        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), RecvError> {
            unimplemented!()
        }
    }

    impl Endpoint<ConnectionMapMock, SocketMock> {
        fn bind() -> Self {
            Self {
                connection_map: ConnectionMapMock,
                socket: SocketMock,
                endpoint_type: EndpointType::Server,
            }
        }
    }

    let ep = Endpoint::bind();

    let packet = LongHeaderPacket::new_client_hello_packet_v1(&PacketNumber::new(), None)?;
    let packet_length = ep.client_hello_v1(
        &ConnectionRfc9000 {
            initial_space: crate::space::InitialSpaceRfc9000,
            handshake_space: crate::space::HandshakeSpaceRfc9000,
            app_space: crate::space::AppDataSpaceRfc9000,
        },
        &packet,
        &SocketAddr::from_str("127.0.0.1:4443")?,
    )?;
    assert_eq!(packet_length, packet.vec_len());

    Ok(())
}
