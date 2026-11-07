#![allow(clippy::many_single_char_names)]
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use awak::net::{TcpStream, UdpSocket};
use awak::time::timeout;
use awak::util::{copy_bidirectional, IdleTimeout};
use futures_channel::mpsc::{channel, Receiver, Sender};
use futures_util::{future::join, AsyncRead, AsyncReadExt, AsyncWrite, Stream};

use crate::cipher::Cipher;
use crate::config::{self, Addr, Network};
use crate::listener::{self, Listener};
use crate::resolver::resolve;
use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};
use crate::udp2022::{PacketWindow, Udp2022};
use crate::util::generate_raw_addr;
use crate::CipherStream;
use crate::{DEFAULT_CHECK_INTERVAL, DEFAULT_IDLE_TIMEOUT};

const DEFAULT_GET_ADDR_INFO_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_RESLOVE_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UDP_BUFFER_SIZE: usize = 65536;
/// How long an AEAD-2022 UDP session (and its server session id / packet
/// counter) is kept alive after the last packet.
const DEFAULT_UDP2022_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Per client-session state for AEAD-2022 UDP.
///
/// SIP022 derives the server -> client key from a *server* session id and seals
/// every response with an increasing packet id, so the server has to remember
/// both for the lifetime of the session.
struct Udp2022Sessions {
    sessions: Mutex<HashMap<u64, Udp2022Session>>,
}

struct Udp2022Session {
    server_session_id: u64,
    next_packet_id: u64,
    window: PacketWindow,
    last_seen: Instant,
}

impl Udp2022Sessions {
    fn new() -> Udp2022Sessions {
        Udp2022Sessions {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Look up (or create) the session for `client_session_id` and check the
    /// packet id against the replay window. Returns `false` for replays.
    fn accept(&self, client_session_id: u64, packet_id: u64) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, s| now.duration_since(s.last_seen) < DEFAULT_UDP2022_SESSION_TIMEOUT);

        let session = sessions
            .entry(client_session_id)
            .or_insert_with(|| Udp2022Session {
                server_session_id: random_session_id(),
                next_packet_id: 1,
                window: PacketWindow::new(),
                last_seen: now,
            });
        session.last_seen = now;

        session.window.validate(packet_id)
    }

    /// Allocate the `(server_session_id, packet_id)` pair for the next
    /// response. The packet id is incremented before use, so the first
    /// response carries 1.
    fn next(&self, client_session_id: u64) -> (u64, u64) {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, s| now.duration_since(s.last_seen) < DEFAULT_UDP2022_SESSION_TIMEOUT);

        let session = sessions
            .entry(client_session_id)
            .or_insert_with(|| Udp2022Session {
                server_session_id: random_session_id(),
                next_packet_id: 1,
                window: PacketWindow::new(),
                last_seen: now,
            });
        session.last_seen = now;

        let packet_id = session.next_packet_id;
        session.next_packet_id = session.next_packet_id.wrapping_add(1);
        (session.server_session_id, packet_id)
    }
}

fn random_session_id() -> u64 {
    let mut buf = [0u8; 8];
    rand::fill(&mut buf[..]);
    let id = u64::from_be_bytes(buf);
    if id == 0 {
        1
    } else {
        id
    }
}

pub struct Server {
    services: Vec<Service>,
}

impl Server {
    pub fn new(configs: Vec<config::Server>) -> Server {
        let services = configs.into_iter().map(Service::new).collect();
        Server { services }
    }

    pub fn serve(self) {
        for s in self.services {
            awak::spawn(async move {
                if let Err(e) = s.serve().await {
                    log::error!("server fail: {:?}", e);
                }
            })
            .detach();
        }
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
        let cipher = Cipher::new(self.config.method, &self.config.password)?;
        let listener = Listener::bind(self.config.local_addr.clone()).await?;
        log::info!("listening on {:?}", self.config.local_addr);
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
        match self.config.network {
            Network::Tcp => self.stream_relay().await,
            Network::Udp => self.packet_relay().await,
            Network::Both => {
                let fut1 = self.stream_relay();
                let fut2 = self.packet_relay();
                let _ = join(fut1, fut2).await;
                Ok(())
            }
        }
    }

    pub async fn packet_relay(&self) -> io::Result<()> {
        let cipher = Cipher::new(self.config.method, &self.config.password)?;
        let addr = match &self.config.local_addr {
            Addr::Path(addr) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid local_addr {addr:?}"),
                ));
            }
            Addr::Socket(addr) => addr,
        };
        let socket = listener::bind_udp(*addr)?;
        log::info!("listening udp on {:?}", self.config.local_addr);
        UdpRelay::new(socket, cipher).await
    }
}

struct UdpRelay {
    buf: [u8; MAX_UDP_BUFFER_SIZE],
    sender: Sender<(Vec<u8>, SocketAddr)>,
    receiver: Receiver<(Vec<u8>, SocketAddr)>,
    socket: UdpSocket,
    recv: Option<(Vec<u8>, SocketAddr)>,
    cipher: Cipher,
    sessions: Arc<Udp2022Sessions>,
}

impl UdpRelay {
    fn new(socket: UdpSocket, cipher: Cipher) -> UdpRelay {
        let (sender, receiver) = channel(1024);
        UdpRelay {
            buf: [0u8; MAX_UDP_BUFFER_SIZE],
            sender,
            receiver,
            socket,
            recv: None,
            cipher,
            sessions: Arc::new(Udp2022Sessions::new()),
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
                    let sessions = Arc::clone(&me.sessions);
                    awak::spawn(async move {
                        if let Err(e) = proxy_packet(cipher, buf, peer_addr, sender, sessions).await
                        {
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
    mut cipher: Cipher,
    mut buf: Vec<u8>,
    peer_addr: SocketAddr,
    mut sender: Sender<(Vec<u8>, SocketAddr)>,
    sessions: Arc<Udp2022Sessions>,
) -> io::Result<(u64, u64)> {
    if cipher.is_aead2022() {
        return proxy_packet_2022(cipher, buf, peer_addr, sender, sessions).await;
    }
    if buf.len() < cipher.iv_or_salt_len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "UnexpectedEof",
        ));
    }
    let iv_or_salt_len = cipher.iv_or_salt_len();
    cipher
        .decrypt_iv_or_salt_mut()
        .copy_from_slice(&buf[..iv_or_salt_len]);
    cipher.init_decrypt();
    buf.drain(..iv_or_salt_len);

    // decrypt recv data.
    cipher.decrypt_in_place(&mut buf)?;
    if cipher.is_aead() {
        buf.drain(buf.len() - cipher.tag_size()..);
    }

    // get host and port.
    let (n, host, port) = get_addr_info(&mut buf.as_slice()).await?;
    log::debug!("proxy to address: {}:{}", host, port);
    buf.drain(..n);

    // resolver host if need.
    let addr = timeout(DEFAULT_RESLOVE_TIMEOUT, resolve(&host)).await??;
    log::debug!("resolver addr to ip: {}", addr);
    let local: SocketAddr = if addr.is_ipv4() {
        ([0u8; 4], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };

    // send to and recv from target.
    let socket = UdpSocket::bind(local)?;
    socket.connect((addr, port))?;
    let _ = socket.send(&buf).await?;
    let mut recv_buf = vec![0u8; MAX_UDP_BUFFER_SIZE];
    let n = socket.recv(&mut recv_buf).await?;
    recv_buf.truncate(n);

    // encrypt return data.
    // A UDP datagram is self-contained: there is no stream handshake that could
    // carry the salt, so every response is prefixed with a fresh salt/IV.
    cipher.init_encrypt();
    let salt_len = cipher.iv_or_salt_len();
    let mut data = cipher.encrypt_iv_or_salt().to_vec();
    data.extend_from_slice(&generate_raw_addr(&addr.to_string(), port));
    data.extend_from_slice(&recv_buf);
    if cipher.is_aead() {
        data.extend_from_slice(&vec![0u8; cipher.tag_size()]);
    }
    cipher.encrypt_in_place(&mut data[salt_len..])?;

    sender
        .try_send((data, peer_addr))
        .map_err(|e| io::Error::other(format!("send fail: {e}")))?;
    Ok((buf.len() as u64, n as u64))
}

/// Relay a single AEAD-2022 (SIP022) UDP datagram.
async fn proxy_packet_2022(
    cipher: Cipher,
    buf: Vec<u8>,
    peer_addr: SocketAddr,
    mut sender: Sender<(Vec<u8>, SocketAddr)>,
    sessions: Arc<Udp2022Sessions>,
) -> io::Result<(u64, u64)> {
    let udp = Udp2022::new(cipher.method(), cipher.key())?;
    let request = udp.decrypt_client_packet(&buf)?;
    if !sessions.accept(request.client_session_id, request.packet_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "replayed 2022 udp packet: session {:x}, packet id {}",
                request.client_session_id, request.packet_id
            ),
        ));
    }
    log::debug!(
        "2022 udp session {:x} packet {} -> {}:{}",
        request.client_session_id,
        request.packet_id,
        request.host,
        request.port
    );

    let addr = timeout(DEFAULT_RESLOVE_TIMEOUT, resolve(&request.host)).await??;
    let local: SocketAddr = if addr.is_ipv4() {
        ([0u8; 4], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };

    let socket = UdpSocket::bind(local)?;
    let _ = socket
        .send_to(&request.payload, (addr, request.port))
        .await?;
    let mut recv_buf = vec![0u8; MAX_UDP_BUFFER_SIZE];
    let (n, src) = socket.recv_from(&mut recv_buf).await?;

    let (server_session_id, packet_id) = sessions.next(request.client_session_id);
    let data = udp.encrypt_server_packet(
        server_session_id,
        packet_id,
        request.client_session_id,
        &src.ip().to_string(),
        src.port(),
        &recv_buf[..n],
    )?;

    sender
        .try_send((data, peer_addr))
        .map_err(|e| io::Error::other(format!("send fail: {e}")))?;
    Ok((request.payload.len() as u64, n as u64))
}

async fn proxy<A>(cipher: Cipher, socket1: &mut A) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let is_aead2022 = cipher.is_aead2022();
    let socket1 = &mut CipherStream::remote(cipher, socket1);
    let (_, host, port) = timeout(DEFAULT_GET_ADDR_INFO_TIMEOUT, get_addr_info(socket1))
        .await
        .map_err(|e| io::Error::other(format!("get addr info timeout: {e:?}")))?
        .map_err(|e| io::Error::other(format!("get addr info fail: {e:?}")))?;
    log::debug!("proxy to address: {}:{}", host, port);

    if is_aead2022 {
        let buf = &mut [0u8; 2];
        socket1.read_exact(buf).await?;
        let padding_len = u16::from_be_bytes([buf[0], buf[1]]);
        let mut padding = vec![0u8; padding_len as usize];
        socket1.read_exact(&mut padding).await?;
    }

    let addr = timeout(DEFAULT_RESLOVE_TIMEOUT, resolve(&host))
        .await
        .map_err(|e| io::Error::other(format!("resolve timeout: {e:?}")))?
        .map_err(|e| io::Error::other(format!("resolve fail: {e:?}")))?;
    log::debug!("resolver addr to ip: {}", addr);

    let mut socket2 = timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect((addr, port)))
        .await
        .map_err(|e| io::Error::other(format!("connect timeout: {e:?}")))?
        .map_err(|e| io::Error::other(format!("connect fail: {e:?}")))?;
    let _ = socket2.set_nodelay(true);
    log::debug!("connected to addr {}:{}", addr, port);

    let (n1, n2) = IdleTimeout::new(
        copy_bidirectional(&mut socket2, socket1),
        DEFAULT_IDLE_TIMEOUT,
        DEFAULT_CHECK_INTERVAL,
    )
    .await
    .map_err(|e| io::Error::other(format!("idle timeout: {e:?}")))?
    .map_err(|e| io::Error::other(format!("copy bidirectional fail: {e:?}")))?;
    log::debug!("proxy local => remote: {}, remote => local: {}", n1, n2);
    Ok((n1, n2))
}

async fn get_addr_info<A>(conn: &mut A) -> io::Result<(usize, String, u16)>
where
    A: AsyncRead + Unpin + ?Sized,
{
    let address_type = &mut [0u8; 1];
    conn.read_exact(address_type).await?;
    match address_type.first() {
        // For IPv4 addresses, we read the 4 bytes for the address as
        // well as 2 bytes for the port.
        Some(&TYPE_IPV4) => {
            let buf = &mut [0u8; 6];
            conn.read_exact(buf).await?;
            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
            Ok((7, format!("{addr}"), port))
        }
        // For IPv6 addresses there's 16 bytes of an address plus two
        // bytes for a port, so we read that off and then keep going.
        Some(&TYPE_IPV6) => {
            let buf = &mut [0u8; 18];
            conn.read_exact(buf).await?;
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
            Ok((19, format!("{addr}"), port))
        }
        // The SOCKSv5 protocol not only supports proxying to specific
        // IP addresses, but also arbitrary hostnames.
        Some(&TYPE_DOMAIN) => {
            let buf1 = &mut [0u8];
            conn.read_exact(buf1).await?;
            let buf2 = &mut vec![0u8; buf1[0] as usize + 2];
            conn.read_exact(buf2).await?;
            let hostname = &buf2[..buf2.len() - 2];
            let hostname = if let Ok(hostname) = str::from_utf8(hostname) {
                hostname
            } else {
                return Err(io::Error::other("hostname include invalid utf8"));
            };
            let pos = buf2.len() - 2;
            let port = ((buf2[pos] as u16) << 8) | (buf2[pos + 1] as u16);
            Ok((2 + buf2.len(), hostname.to_string(), port))
        }
        n => {
            log::error!("unknown address type, received: {:?}", n);
            Err(io::Error::other("unknown address type, received"))
        }
    }
}
