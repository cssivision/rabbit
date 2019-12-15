use std::io::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shadowsocks::args::parse_args;
use shadowsocks::cipher::Cipher;
use shadowsocks::config::Config;
use shadowsocks::io::{decrypt_copy, encrypt_copy, read_exact};
use shadowsocks::resolver::resolve;
use shadowsocks::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};
use shadowsocks::util::other;

use futures::future::try_join;
use futures::FutureExt;
use log::{debug, error};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let config = parse_args("ssserver").expect("invalid config");
    println!("{}", serde_json::to_string_pretty(&config).unwrap());
    let cipher = Cipher::new(&config.method, &config.password);
    let mut listener = TcpListener::bind(&config.server_addr).await?;

    loop {
        let config = config.clone();
        let (socket, _) = listener.accept().await?;
        let cipher = Arc::new(Mutex::new(cipher.reset()));

        let proxy = proxy(config.clone(), cipher, socket).map(|r| {
            if let Err(e) = r {
                error!("failed to proxy; error={}", e);
            }
        });

        tokio::spawn(proxy);
    }
}

async fn proxy(
    config: Config,
    cipher: Arc<Mutex<Cipher>>,
    mut socket1: TcpStream,
) -> Result<(u64, u64), Error> {
    let (host, port) = get_addr_info(cipher.clone(), &mut socket1).await?;
    println!("proxy to address: {}:{}", host, port);

    let addr = resolve(&host).await?;
    debug!("resolver addr to ip: {}", addr);

    let mut socket2 = TcpStream::connect(&SocketAddr::new(addr, port)).await?;

    let keepalive_period = config.keepalive_period;
    let _ = socket1.set_keepalive(Some(Duration::new(keepalive_period, 0)))?;
    let _ = socket2.set_keepalive(Some(Duration::new(keepalive_period, 0)))?;

    let (mut socket1_reader, mut socket1_writer) = socket1.split();
    let (mut socket2_reader, mut socket2_writer) = socket2.split();
    let half1 = decrypt_copy(cipher.clone(), &mut socket1_reader, &mut socket2_writer);
    let half2 = encrypt_copy(cipher.clone(), &mut socket2_reader, &mut socket1_writer);

    let (n1, n2) = try_join(half1, half2).await?;
    debug!("proxy local => remote: {}, remote => local: {}", n1, n2);
    Ok((n1, n2))
}

async fn get_addr_info(
    cipher: Arc<Mutex<Cipher>>,
    conn: &mut TcpStream,
) -> Result<(String, u16), Error> {
    let t = &mut vec![0u8; 1];
    let _ = read_exact(cipher.clone(), conn, t).await?;

    match t[0] {
        // For IPv4 addresses, we read the 4 bytes for the address as
        // well as 2 bytes for the port.
        TYPE_IPV4 => {
            let buf = &mut vec![0u8; 6];
            let _ = read_exact(cipher.clone(), conn, buf).await?;
            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
            return Ok((format!("{}", addr), port));
        }
        // For IPv6 addresses there's 16 bytes of an address plus two
        // bytes for a port, so we read that off and then keep going.
        TYPE_IPV6 => {
            let buf = &mut vec![0u8; 18];

            let _ = read_exact(cipher.clone(), conn, buf).await?;

            let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
            let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
            let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
            let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
            let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
            let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
            let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
            let h = ((buf[14] as u16) << 8) | (buf[15] as u16);

            let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
            let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
            return Ok((format!("{}", addr), port));
        }
        // The SOCKSv5 protocol not only supports proxying to specific
        // IP addresses, but also arbitrary hostnames.
        TYPE_DOMAIN => {
            let buf1 = &mut vec![0u8];
            let _ = read_exact(cipher.clone(), conn, buf1).await?;
            let buf2 = &mut vec![0u8; buf1[0] as usize + 2];
            let _ = read_exact(cipher.clone(), conn, buf2).await?;

            let hostname = &buf2[..buf2.len() - 2];
            let hostname = if let Ok(hostname) = str::from_utf8(hostname) {
                hostname
            } else {
                return Err(other("hostname include invalid utf8"));
            };

            let pos = buf2.len() - 2;
            let port = ((buf2[pos] as u16) << 8) | (buf2[pos + 1] as u16);
            return Ok((hostname.to_string(), port));
        }
        n => {
            error!("unknown address type, received: {}", n);
            return Err(other("unknown address type, received"));
        }
    }
}
