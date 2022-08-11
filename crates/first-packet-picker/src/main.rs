fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn = std::net::UdpSocket::bind("localhost:4433")?;

    // > Clients MUST ensure that UDP datagrams containing
    // > Initial packets have UDP payloads of at least 1200 bytes,
    // Initial Packet は必ず1200バイト以上になります。
    // quiche version0.14.0 の場合は1200バイトまでパディングで埋められているだけなので、
    // 1200バイトとれば十分です。よって、ここではバッファーを1200バイトにしています。
    let mut buf = vec![0; 1200];
    _ = conn.recv(&mut buf)?;

    print!("{}", unsafe { String::from_utf8_unchecked(buf) });

    Ok(())
}
