use std::io::Error;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use shadowsocks::args::parse_args;
use shadowsocks::cipher::Cipher;
use shadowsocks::config::Config;
use shadowsocks::io::{decrypt_copy, encrypt_copy, write_all};
use shadowsocks::socks5::{
    self,
    v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6},
};

use awak::net::{TcpListener, TcpStream};
use futures_util::future::{select, Either};
use futures_util::FutureExt;
use parking_lot::Mutex;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let config = parse_args("sslocal").unwrap();
    log::info!("{}", serde_json::to_string_pretty(&config).unwrap());

    awak::block_on(async {
        let listener = TcpListener::bind(&config.local_addr).await?;
        log::info!("listening connections on {}", config.local_addr);

        let cipher = Cipher::new(&config.method, &config.password);
        let config = Arc::new(config);

        loop {
            let (socket, addr) = listener.accept().await?;
            let _ = socket.set_nodelay(true);
            log::debug!("accept tcp stream from addr {:?}", addr);
            let cipher = Arc::new(Mutex::new(cipher.reset()));
            let proxy = proxy(config.clone(), cipher, socket).map(|r| {
                if let Err(e) = r {
                    log::error!("failed to proxy; error={}", e);
                }
            });
            awak::spawn(proxy).detach();
        }
    })
}

async fn proxy(
    config: Arc<Config>,
    cipher: Arc<Mutex<Cipher>>,
    mut socket1: TcpStream,
) -> Result<(u64, u64), Error> {
    let (host, port) = socks5::handshake(&mut socket1, Duration::from_secs(3)).await?;

    log::debug!("proxy to address: {}:{}", host, port);

    let mut socket2 = TcpStream::connect(&config.server_addr).await?;
    log::debug!("connected to server {}", config.server_addr);

    let rawaddr = generate_raw_addr(&host, port);
    write_all(cipher.clone(), &mut socket2, &rawaddr).await?;

    let keepalive_period = config.keepalive_period;
    socket1.set_keepalive(Some(Duration::from_secs(keepalive_period)))?;
    socket2.set_keepalive(Some(Duration::from_secs(keepalive_period)))?;

    let (mut socket1_reader, mut socket1_writer) = socket1.split();
    let (mut socket2_reader, mut socket2_writer) = socket2.split();

    log::debug!("transport data between local and remote...");
    let half1 = encrypt_copy(cipher.clone(), &mut socket1_reader, &mut socket2_writer);
    let half2 = decrypt_copy(cipher.clone(), &mut socket2_reader, &mut socket1_writer);

    let (n1, n2) = match select(half1, half2).await {
        Either::Left((n, half2)) => {
            let n1 = n?;
            let n2 = half2.amt();
            (n1, n2)
        }
        Either::Right((n, half1)) => {
            let n2 = n?;
            let n1 = half1.amt();
            (n1, n2)
        }
    };
    log::debug!("proxy local => remote: {}, remote => local: {:?}", n1, n2);
    Ok((0, 0))
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
