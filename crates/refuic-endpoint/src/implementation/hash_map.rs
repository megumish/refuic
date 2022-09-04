use std::net::SocketAddr;

use refuic_common::EndpointType;

use crate::Endpoint;

use super::std::Socket;

mod app;
mod connection;
mod crypto_kit;
mod transport_parameter;

pub type HashMapEndpoint = Endpoint<
    connection::Repository,
    crypto_kit::Repository,
    app::Repository,
    transport_parameter::Repository,
    Socket,
>;
impl
    Endpoint<
        connection::Repository,
        crypto_kit::Repository,
        app::Repository,
        transport_parameter::Repository,
        Socket,
    >
{
    pub fn new_server(socket_address: SocketAddr) -> Self {
        Self {
            connection_repository: Default::default(),
            crypto_kit_repository: Default::default(),
            app_repository: Default::default(),
            transport_parameter_repository: Default::default(),
            socket: Socket::new(socket_address),
            endpoint_type: EndpointType::Server,
        }
    }
}
