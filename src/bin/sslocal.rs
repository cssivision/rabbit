use std::io::Error;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shadowsocks::args::parse_args;
use shadowsocks::cipher::Cipher;
use shadowsocks::config::Config;
use shadowsocks::io::{decrypt_copy, encrypt_copy, write_all};
use shadowsocks::socks5::{
    self,
    v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6},
};
use shadowsocks::util::other;

use awak::net::{TcpListener, TcpStream};
use awak::time::timeout;
use futures_util::future::try_join;
use futures_util::FutureExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let config = parse_args("sslocal").unwrap();
    log::info!("{}", serde_json::to_string_pretty(&config).unwrap());

    awak::block_on(async {
        let listener = TcpListener::bind(&config.local_addr).await?;
        log::info!("Listening connections on {}", config.local_addr);

        let cipher = Cipher::new(&config.method, &config.password);
        let config = Arc::new(config);

        loop {
            let (socket, _) = listener.accept().await?;
            let cipher = Arc::new(Mutex::new(cipher.reset()));

            let proxy = proxy(config.clone(), cipher, socket).map(|r| {
                if let Err(e) = r {
                    log::error!("failed to proxy; error={}", e);
                }
            });

            awak::spawn(proxy);
        }
    })
}

async fn proxy(
    config: Arc<Config>,
    cipher: Arc<Mutex<Cipher>>,
    mut socket1: TcpStream,
) -> Result<(u64, u64), Error> {
    let socks5_serve = timeout(Duration::from_secs(1), socks5::serve(&mut socket1)).await?;
    if socks5_serve.is_err() {
        return Err(other("socks5 handshake timout"));
    }
    let (host, port) = socks5_serve.unwrap();
    log::info!("proxy to address: {}:{}", host, port);

    let mut socket2 = TcpStream::connect(&config.server_addr).await?;
    let rawaddr = generate_raw_addr(&host, port);
    write_all(cipher.clone(), &mut socket2, &rawaddr).await?;

    let keepalive_period = config.keepalive_period;
    socket1.set_keepalive(Some(Duration::from_secs(keepalive_period)))?;
    socket2.set_keepalive(Some(Duration::from_secs(keepalive_period)))?;

    let (mut socket1_reader, mut socket1_writer) = socket1.split();
    let (mut socket2_reader, mut socket2_writer) = socket2.split();
    let half1 = encrypt_copy(cipher.clone(), &mut socket1_reader, &mut socket2_writer);
    let half2 = decrypt_copy(cipher.clone(), &mut socket2_reader, &mut socket1_writer);

    let (n1, n2) = try_join(half1, half2).await?;
    log::debug!("proxy local => remote: {}, remote => local: {}", n1, n2);
    Ok((n1, n2))
}

fn generate_raw_addr(host: &str, port: u16) -> Vec<u8> {
    match IpAddr::from_str(host) {
        Ok(IpAddr::V4(host)) => {
            let mut rawaddr = vec![TYPE_IPV4];
            rawaddr.extend_from_slice(&host.octets());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
        Ok(IpAddr::V6(host)) => {
            let mut rawaddr = vec![TYPE_IPV6];
            rawaddr.extend_from_slice(&host.octets());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
        _ => {
            let dm_len = host.as_bytes().len();
            let mut rawaddr = vec![TYPE_DOMAIN, dm_len as u8];
            rawaddr.extend_from_slice(host.as_bytes());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
    }
}
