use std::future::pending;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use awak::net::TcpStream;
use awak::time::timeout;
use futures_util::{AsyncRead, AsyncWrite};

use crate::cipher::Cipher;
use crate::config;
use crate::io::{copy_bidirectional, write_all, IdleTimeout, DEFAULT_IDLE_TIMEOUT};
use crate::listener::Listener;
use crate::socks5::{
    self,
    v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6},
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

pub struct Server {
    services: Vec<Service>,
}

impl Server {
    pub fn new(configs: Vec<config::Client>) -> Server {
        let services = configs.into_iter().map(Service::new).collect();
        Server { services }
    }

    pub async fn serve(self) {
        for s in self.services {
            awak::spawn(async move {
                if let Err(e) = s.serve().await {
                    log::error!("server fail: {:?}", e);
                }
            })
            .detach();
        }
        pending().await
    }
}

pub struct Service {
    config: config::Client,
}

impl Service {
    pub fn new(config: config::Client) -> Service {
        Service { config }
    }

    pub async fn serve(&self) -> io::Result<()> {
        let cipher = Cipher::new(&self.config.method, &self.config.password);
        let local_addr = self.config.local_addr.clone();
        let listener = Listener::bind(local_addr).await?;
        log::info!("listening connections on {:?}", self.config.local_addr);
        loop {
            let mut socket = listener.accept().await?;
            let cipher = cipher.reset();
            let server_addr = self.config.server_addr;
            let proxy = async move {
                if let Err(e) = proxy(server_addr, cipher, &mut socket).await {
                    log::error!("failed to proxy; error={}", e);
                }
            };
            awak::spawn(proxy).detach();
        }
    }
}

async fn proxy<A>(
    server_addr: SocketAddr,
    cipher: Cipher,
    socket1: &mut A,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let cipher = Arc::new(Mutex::new(cipher));

    let (host, port) = socks5::handshake(socket1, Duration::from_secs(3)).await?;
    log::debug!("proxy to address: {}:{}", host, port);

    let mut socket2 = timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect(&server_addr)).await??;
    log::debug!("connected to server {}", server_addr);

    let rawaddr = generate_raw_addr(&host, port);
    write_all(cipher.clone(), &mut socket2, &rawaddr).await?;

    let (n1, n2) = IdleTimeout::new(
        copy_bidirectional(socket1, &mut socket2, cipher),
        DEFAULT_IDLE_TIMEOUT,
    )
    .await??;
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
