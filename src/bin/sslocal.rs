use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use awak::io::{AsyncRead, AsyncWrite};
use awak::net::TcpStream;
use shadowsocks::args::parse_args;
use shadowsocks::cipher::Cipher;
use shadowsocks::config::Config;
use shadowsocks::io::{copy_bidirectional, write_all};
use shadowsocks::listener::Listener;
use shadowsocks::socks5::{
    self,
    v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6},
};

fn main() -> io::Result<()> {
    env_logger::init();
    let config = parse_args("sslocal").unwrap();
    log::info!("{}", serde_json::to_string_pretty(&config).unwrap());
    let cipher = Cipher::new(&config.method, &config.password);
    let config = Arc::new(config);
    awak::block_on(async {
        let listener = Listener::bind(&config.local_addr, config.unix_socket).await?;
        log::info!("listening connections on {}", config.local_addr);
        loop {
            let mut socket = listener.accept().await?;
            let cipher = cipher.reset();
            let config = config.clone();
            let proxy = async move {
                if let Err(e) = proxy(config, cipher, &mut socket).await {
                    log::error!("failed to proxy; error={}", e);
                }
            };
            awak::spawn(proxy).detach();
        }
    })
}

async fn proxy<A>(config: Arc<Config>, cipher: Cipher, socket1: &mut A) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let cipher = Arc::new(Mutex::new(cipher));

    let (host, port) = socks5::handshake(socket1, Duration::from_secs(3)).await?;
    log::debug!("proxy to address: {}:{}", host, port);

    let mut socket2 = TcpStream::connect(&config.server_addr).await?;
    log::debug!("connected to server {}", config.server_addr);

    let rawaddr = generate_raw_addr(&host, port);
    write_all(cipher.clone(), &mut socket2, &rawaddr).await?;

    let (n1, n2) = copy_bidirectional(socket1, &mut socket2, cipher).await?;
    log::debug!("proxy local => remote: {}, remote => local: {:?}", n1, n2);
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
