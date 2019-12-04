use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::io::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{debug, error};

use shadowsocks_rs as shadowsocks;
use shadowsocks::args::parse_args;
use shadowsocks::cipher::Cipher;
use shadowsocks::io::{decrypt_copy, encrypt_copy, write_all};
use shadowsocks::socks5::{
    self,
    v5::{TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN},
};
use shadowsocks::config::Config;

use futures::FutureExt;
use futures::future::try_join;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let config = parse_args("sslocal").unwrap();
    println!("{}", serde_json::to_string_pretty(&config).unwrap());

    let mut listener = TcpListener::bind(&config.local_addr).await?;
    println!("Listening connections on {}", config.local_addr);
    let cipher = Cipher::new(&config.method, &config.password);
    
    
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

async fn proxy(config: Config, cipher: Arc<Mutex<Cipher>>, mut socket1: TcpStream) -> Result<(u64, u64), Error> {
    let (host, port) = socks5::serve(&mut socket1).await?;
    println!("proxy to address: {}:{}", host, port);

    let mut socket2 = TcpStream::connect(&config.server_addr).await?;
    let rawaddr = generate_raw_addr(&host, port);
    write_all(cipher.clone(), &mut socket2, &rawaddr).await?;

    let keepalive_period = config.keepalive_period;
    let _ = socket1.set_keepalive(Some(Duration::new(keepalive_period, 0)))?;
    let _ = socket2.set_keepalive(Some(Duration::new(keepalive_period, 0)))?;

    let (mut socket1_reader, mut socket1_writer) = socket1.split();
    let (mut socket2_reader, mut socket2_writer) = socket2.split();
    let half1 = encrypt_copy(cipher.clone(), &mut socket1_reader, &mut socket2_writer);
    let half2 = decrypt_copy(cipher.clone(), &mut socket2_reader, &mut socket1_writer);

    let (n1, n2) = try_join(half1, half2).await?;
    debug!("proxy local => remote: {}, remote => local: {}", n1, n2);
    Ok((n1, n2))
}

fn generate_raw_addr(host: &str, port: u16) -> Vec<u8> {
    if let Ok(host) = Ipv4Addr::from_str(host) {
        let mut rawaddr = vec![TYPE_IPV4];
        rawaddr.extend_from_slice(&host.octets());
        rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
        return rawaddr;
    }

    if let Ok(host) = Ipv6Addr::from_str(host) {
        let mut rawaddr = vec![TYPE_IPV6];
        rawaddr.extend_from_slice(&host.octets());
        rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
        return rawaddr;
    }

    let dm_len = host.as_bytes().len();
    let mut rawaddr = vec![TYPE_DOMAIN, dm_len as u8];
    rawaddr.extend_from_slice(host.as_bytes());
    rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
    return rawaddr;
}
