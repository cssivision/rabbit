#![allow(clippy::many_single_char_names)]
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;
use std::sync::{Arc, Mutex};

use awak::io::{AsyncRead, AsyncWrite};
use awak::net::TcpStream;

use crate::cipher::Cipher;
use crate::config::Config;
use crate::io::{copy_bidirectional, read_exact};
use crate::listener::Listener;
use crate::pending;
use crate::resolver::resolve;
use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};
use crate::util::other;

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
        pending().await;
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
        let listener = Listener::bind(&self.config.server_addr, self.config.unix_socket).await?;
        log::info!("listening connections on {}", self.config.server_addr);
        loop {
            let mut socket = listener.accept().await?;
            let cipher = cipher.reset();
            let proxy = async move {
                if let Err(e) = proxy(cipher, &mut socket).await {
                    log::error!("failed to proxy; error={}", e);
                };
            };
            awak::spawn(proxy).detach();
        }
    }
}

async fn proxy<A>(cipher: Cipher, socket1: &mut A) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let cipher = Arc::new(Mutex::new(cipher));
    let (host, port) = get_addr_info(cipher.clone(), socket1).await?;
    log::debug!("proxy to address: {}:{}", host, port);

    let addr = resolve(&host).await?;
    log::debug!("resolver addr to ip: {}", addr);

    let mut socket2 = TcpStream::connect(&SocketAddr::new(addr, port)).await?;
    let _ = socket2.set_nodelay(true);
    log::debug!("connected to addr {}:{}", addr, port);

    let (n1, n2) = copy_bidirectional(&mut socket2, socket1, cipher).await?;
    log::debug!("proxy local => remote: {}, remote => local: {}", n1, n2);
    Ok((n1, n2))
}

async fn get_addr_info<A>(cipher: Arc<Mutex<Cipher>>, conn: &mut A) -> io::Result<(String, u16)>
where
    A: AsyncRead + Unpin + ?Sized,
{
    let address_type = &mut vec![0u8; 1];
    let _ = read_exact(cipher.clone(), conn, address_type).await?;

    match address_type.get(0) {
        // For IPv4 addresses, we read the 4 bytes for the address as
        // well as 2 bytes for the port.
        Some(&TYPE_IPV4) => {
            let buf = &mut vec![0u8; 6];
            let _ = read_exact(cipher.clone(), conn, buf).await?;
            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
            Ok((format!("{}", addr), port))
        }
        // For IPv6 addresses there's 16 bytes of an address plus two
        // bytes for a port, so we read that off and then keep going.
        Some(&TYPE_IPV6) => {
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
            Ok((format!("{}", addr), port))
        }
        // The SOCKSv5 protocol not only supports proxying to specific
        // IP addresses, but also arbitrary hostnames.
        Some(&TYPE_DOMAIN) => {
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
            Ok((hostname.to_string(), port))
        }
        n => {
            log::error!("unknown address type, received: {:?}", n);
            Err(other("unknown address type, received"))
        }
    }
}
