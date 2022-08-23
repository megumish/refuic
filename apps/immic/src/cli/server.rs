use std::net::UdpSocket;

use clap::Parser;
use der::PemReader;
use ed25519_dalek::Keypair;
use immic_common::{EndpointType, QuicVersion};
use immic_frame::frame;
use immic_packet::long;
use immic_tls::signature_scheme::SignatureScheme;
use rand::{rngs::StdRng, SeedableRng};
use x509_cert::der::Decode;

use crate::error::Error;

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Cli {
    #[clap(value_parser)]
    address: String,
}

impl Cli {
    pub fn run(self) -> Result<(), Error> {
        let socket = UdpSocket::bind(self.address)?;

        let certificate_bytes = include_bytes!("./cacert.der");

        // PEM形式だとなぜか読み込めないので、DER形式に変換したものを使う
        let certificate = x509_cert::Certificate::from_der(certificate_bytes).unwrap();
        let cert_signature_scheme =
            SignatureScheme::from_oid(&certificate.signature_algorithm.oid).unwrap();
        eprintln!("{:?}", cert_signature_scheme);
        let cert_signature = certificate.signature.as_bytes().unwrap();
        {
            let mut buf = vec![0; 1200];
            let (_, peer_addr) = socket.recv_from(&mut buf)?;

            // https://www.rfc-editor.org/rfc/rfc9000.html#name-example-handshake-flows

            let (server_initial, _keypair, client_hello_data, server_hello_data) = {
                let initial = long::initial::parse_from_bytes(
                    &buf,
                    &QuicVersion::Rfc9000,
                    &EndpointType::Server,
                )?;
                let client_hello_data = {
                    let frames = frame::parse_from_bytes(initial.payload(), &QuicVersion::Rfc9000)?;
                    let crypto_data = frame::crypto::crypto_data(&frames)?;
                    immic_tls::handshake::client_hello::parse_from_bytes(&crypto_data)?
                };
                let mut random_generator = StdRng::from_entropy();
                let keypair: Keypair = Keypair::generate(&mut random_generator);
                let server_initial =
                    initial.server_initial(&client_hello_data, keypair.public.as_bytes());
                let server_hello_data = {
                    let frames =
                        frame::parse_from_bytes(server_initial.payload(), &QuicVersion::Rfc9000)?;
                    let crypto_data = frame::crypto::crypto_data(&frames)?;
                    immic_tls::handshake::server_hello::parse_from_bytes(&crypto_data)?
                };
                (
                    initial.server_initial(&client_hello_data, keypair.public.as_bytes()),
                    keypair.secret,
                    client_hello_data,
                    server_hello_data,
                )
            };

            let handshake = server_initial.handshake_server(
                &cert_signature_scheme,
                cert_signature,
                &[client_hello_data.to_vec(), server_hello_data.to_vec()].concat(),
                &server_hello_data.cipher_suite(),
            );

            {
                let mut buf = Vec::new();
                buf.extend(server_initial.protect(&EndpointType::Server)?.to_vec());
                buf.extend(handshake.protect(&EndpointType::Server)?.to_vec());
                // buf.extend(handshake.to_vec());
                let _ = socket.send_to(&buf, peer_addr);
            }
        }
        Ok(())
    }
}
