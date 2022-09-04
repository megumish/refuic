use refuic_endpoint::implementation::hash_map::HashMapEndpoint;

fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();
    let mut server = HashMapEndpoint::new_server("127.0.0.1:4433".parse()?);
    server.recv()?;
    Ok(())
}
