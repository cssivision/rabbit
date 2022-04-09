use std::future::pending;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use awak::net::TcpStream;
use futures_util::{AsyncRead, AsyncWrite};

use crate::cipher::Cipher;
use crate::config::Config;
use crate::io::{copy_bidirectional, write_all};
use crate::listener::Listener;
use crate::socks5::{
    self,
    v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6},
};

pub struct Server {
    services: Vec<Service>,
}

impl Server {
    pub fn new(configs: Vec<Config>) -> Server {
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
    config: Config,
}

impl Service {
    pub fn new(config: Config) -> Service {
        Service { config }
    }

    pub async fn serve(&self) -> io::Result<()> {
        let cipher = Cipher::new(&self.config.method, &self.config.password);
        let listener = Listener::bind(&self.config.local_addr, self.config.unix_socket).await?;
        log::info!("listening connections on {}", self.config.local_addr);
        loop {
            let mut socket = listener.accept().await?;
            let cipher = cipher.reset();
            let server_addr = self.config.server_addr.clone();
            let proxy = async move {
                if let Err(e) = proxy(server_addr, cipher, &mut socket).await {
                    log::error!("failed to proxy; error={}", e);
                }
            };
            awak::spawn(proxy).detach();
        }
    }
}

async fn proxy<A>(server_addr: String, cipher: Cipher, socket1: &mut A) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let cipher = Arc::new(Mutex::new(cipher));

    let (host, port) = socks5::handshake(socket1, Duration::from_secs(3)).await?;
    log::debug!("proxy to address: {}:{}", host, port);

    let mut socket2 = TcpStream::connect(&server_addr).await?;
    log::debug!("connected to server {}", server_addr);

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
