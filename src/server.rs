#![allow(clippy::many_single_char_names)]
use std::future::pending;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use awak::net::{TcpStream, UdpSocket};
use awak::time::timeout;
use futures_util::{future::join, AsyncRead, AsyncWrite, Stream};

use crate::cipher::Cipher;
use crate::config::{self, Addr, Mode};
use crate::io::{copy_bidirectional, read_exact, IdleTimeout, DEFAULT_IDLE_TIMEOUT};
use crate::listener::Listener;
use crate::resolver::resolve;
use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};
use crate::util::other;

const DEFAULT_GET_ADDR_INFO_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_RESLOVE_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UDP_BUFFER_SIZE: usize = 65536;

pub struct Server {
    services: Vec<Service>,
}

impl Server {
    pub fn new(configs: Vec<config::Server>) -> Server {
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
    config: config::Server,
}

impl Service {
    pub fn new(config: config::Server) -> Service {
        Service { config }
    }

    pub async fn stream_relay(&self) -> io::Result<()> {
        let cipher = Cipher::new(&self.config.method, &self.config.password);
        let listener = Listener::bind(self.config.local_addr.clone()).await?;
        log::info!("listening tcp on {:?}", self.config.local_addr);
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

    pub async fn serve(&self) -> io::Result<()> {
        match self.config.mode {
            Mode::Tcp => self.stream_relay().await,
            Mode::Udp => self.packet_relay().await,
            Mode::Both => {
                let fut1 = self.stream_relay();
                let fut2 = self.packet_relay();
                let _ = join(fut1, fut2).await;
                Ok(())
            }
        }
    }

    pub async fn packet_relay(&self) -> io::Result<()> {
        let cipher = Cipher::new(&self.config.method, &self.config.password);
        let addr = match &self.config.local_addr {
            Addr::Path(addr) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid local_addr {:?}", addr),
                ));
            }
            Addr::Socket(addr) => addr,
        };
        let socket = UdpSocket::bind(addr)?;
        log::info!("listening udp on {:?}", self.config.local_addr);
        UdpRelay::new(socket, cipher).await
    }
}

struct UdpRelay {
    buf: [u8; MAX_UDP_BUFFER_SIZE],
    sender: async_channel::Sender<(Vec<u8>, SocketAddr)>,
    receiver: async_channel::Receiver<(Vec<u8>, SocketAddr)>,
    socket: UdpSocket,
    recv: Option<(Vec<u8>, SocketAddr)>,
    cipher: Cipher,
}

impl UdpRelay {
    fn new(socket: UdpSocket, cipher: Cipher) -> UdpRelay {
        let (sender, receiver) = async_channel::unbounded::<(Vec<u8>, SocketAddr)>();
        UdpRelay {
            buf: [0u8; MAX_UDP_BUFFER_SIZE],
            sender,
            receiver,
            socket,
            recv: None,
            cipher,
        }
    }

    fn poll_send_one(&mut self, cx: &Context, data: (Vec<u8>, SocketAddr)) -> Poll<io::Result<()>> {
        match self.socket.poll_send_to(cx, &data.0, data.1) {
            Poll::Pending => {
                self.recv = Some(data);
                Poll::Pending
            }
            Poll::Ready(n) => {
                let _ = n?;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl Future for UdpRelay {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            match me.socket.poll_recv_from(cx, &mut me.buf) {
                Poll::Pending => {
                    if let Some(data) = me.recv.take() {
                        ready!(me.poll_send_one(cx, data))?;
                    }
                    while let Some(data) = ready!(Pin::new(&mut me.receiver).poll_next(cx)) {
                        ready!(me.poll_send_one(cx, data))?;
                    }
                }
                Poll::Ready(v) => {
                    let (n, peer_addr) = v?;
                    log::info!("recv {} byte from {:?}", n, peer_addr);
                    let mut buf = vec![0u8; n];
                    buf.copy_from_slice(&me.buf[..n]);
                    let cipher = me.cipher.reset();
                    let sender = me.sender.clone();
                    awak::spawn(async move {
                        if let Err(e) = proxy_packet(cipher, buf, peer_addr, sender).await {
                            log::error!("failed to proxy; error={}", e);
                        };
                    })
                    .detach();
                }
            }
        }
    }
}

async fn proxy_packet(
    cipher: Cipher,
    mut buf: Vec<u8>,
    peer_addr: SocketAddr,
    sender: async_channel::Sender<(Vec<u8>, SocketAddr)>,
) -> io::Result<(u64, u64)> {
    let cipher = Arc::new(Mutex::new(cipher));

    // get host and port.
    let (host, port) = get_addr_info(cipher.clone(), &mut buf.as_slice()).await?;
    log::debug!("proxy to address: {}:{}", host, port);

    // resolver host if need.
    let addr = timeout(DEFAULT_RESLOVE_TIMEOUT, resolve(&host)).await??;
    log::debug!("resolver addr to ip: {}", addr);
    let local: SocketAddr = if addr.is_ipv4() {
        ([0u8; 4], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };

    // decrypt recv data, dec already init in get_addr_info() function.
    cipher.lock().unwrap().decrypt(&mut buf);

    // send to and recv from target.
    let socket = UdpSocket::bind(&local)?;
    socket.connect((addr, port))?;
    let _ = socket.send(&buf).await?;
    let mut recv_buf = vec![0u8; MAX_UDP_BUFFER_SIZE];
    let n = socket.recv(&mut recv_buf).await?;
    recv_buf.truncate(n);

    // encrypt return data.
    if !cipher.lock().unwrap().is_encrypt_inited() {
        cipher.lock().unwrap().init_encrypt();
    }
    cipher.lock().unwrap().encrypt(&mut recv_buf);
    sender
        .try_send((recv_buf.to_vec(), peer_addr))
        .map_err(|e| other(&format!("send fail: {}", e)))?;
    Ok((buf.len() as u64, n as u64))
}

async fn proxy<A>(cipher: Cipher, socket1: &mut A) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let cipher = Arc::new(Mutex::new(cipher));
    let (host, port) = timeout(
        DEFAULT_GET_ADDR_INFO_TIMEOUT,
        get_addr_info(cipher.clone(), socket1),
    )
    .await??;
    log::debug!("proxy to address: {}:{}", host, port);

    let addr = timeout(DEFAULT_RESLOVE_TIMEOUT, resolve(&host)).await??;
    log::debug!("resolver addr to ip: {}", addr);

    let mut socket2 = timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect((addr, port))).await??;
    let _ = socket2.set_nodelay(true);
    log::debug!("connected to addr {}:{}", addr, port);

    let (n1, n2) = IdleTimeout::new(
        copy_bidirectional(&mut socket2, socket1, cipher),
        DEFAULT_IDLE_TIMEOUT,
    )
    .await??;
    log::debug!("proxy local => remote: {}, remote => local: {}", n1, n2);
    Ok((n1, n2))
}

async fn get_addr_info<A>(cipher: Arc<Mutex<Cipher>>, conn: &mut A) -> io::Result<(String, u16)>
where
    A: AsyncRead + Unpin + ?Sized,
{
    let address_type = &mut vec![0u8; 1];
    let _ = read_exact(cipher.clone(), conn, address_type).await?;

    match address_type.first() {
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
