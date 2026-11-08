use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use awak::net::{TcpStream, UdpSocket};
use awak::time::timeout;
use awak::util::{copy_bidirectional, IdleTimeout};
use bytes::BytesMut;
use futures_channel::mpsc::{channel, Receiver, Sender};
use futures_util::{future::join, AsyncRead, AsyncWrite, AsyncWriteExt, Stream};
use socket2::SockAddr;

use crate::cipher::Cipher;
use crate::config::{self, Network};
use crate::listener;
use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};
use crate::udp2022::{PacketWindow, Udp2022};
use crate::util::generate_raw_addr;
use crate::CipherStream;
use crate::{DEFAULT_CHECK_INTERVAL, DEFAULT_IDLE_TIMEOUT};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UDP_BUFFER_SIZE: usize = 65536;
/// How long an AEAD-2022 UDP association is remembered per local peer.
const DEFAULT_UDP2022_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Client-side state of the AEAD-2022 UDP association with one peer.
struct Udp2022Association {
    client_session_id: u64,
    next_packet_id: u64,
    server_session_id: u64,
    window: PacketWindow,
    last_seen: Instant,
}

struct Udp2022Sessions {
    sessions: Mutex<HashMap<SocketAddr, Udp2022Association>>,
}

impl Udp2022Sessions {
    fn new() -> Udp2022Sessions {
        Udp2022Sessions {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve the packet id of the next outgoing packet.
    fn next_packet_id(&self, peer_addr: SocketAddr) -> (u64, u64) {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, s| now.duration_since(s.last_seen) < DEFAULT_UDP2022_SESSION_TIMEOUT);

        let session = sessions
            .entry(peer_addr)
            .or_insert_with(|| Udp2022Association {
                client_session_id: random_session_id(),
                next_packet_id: 1,
                server_session_id: 0,
                window: PacketWindow::new(),
                last_seen: now,
            });
        session.last_seen = now;

        let packet_id = session.next_packet_id;
        session.next_packet_id = session.next_packet_id.wrapping_add(1);
        (session.client_session_id, packet_id)
    }

    /// Validate a response packet from the server and remember the server
    /// session id it uses.
    fn accept_response(
        &self,
        peer_addr: SocketAddr,
        packet_id: u64,
        server_session_id: u64,
    ) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&peer_addr) {
            session.last_seen = Instant::now();
            if session.server_session_id != 0 && session.server_session_id != server_session_id {
                return false;
            }
            session.server_session_id = server_session_id;
            return session.window.validate(packet_id);
        }
        false
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
    pub fn new(configs: Vec<config::Redir>) -> Server {
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
    config: config::Redir,
}

impl Service {
    pub fn new(config: config::Redir) -> Service {
        Service { config }
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

    pub async fn stream_relay(&self) -> io::Result<()> {
        let cipher = Cipher::new(self.config.method, &self.config.password)?;
        let local_addr = self.config.local_addr;
        let listener = listener::bind_tcp(local_addr)?;
        log::info!("listening connections on {:?}", self.config.local_addr);
        loop {
            let (mut socket, addr) = listener.accept().await?;
            log::debug!("accept stream from addr {:?}", addr);
            let cipher = cipher.reset();
            let server_addr = self.config.server_addr;
            let original_dst_addr = if let Some(addr) = self.config.redir_addr {
                addr
            } else {
                get_original_destination_addr(&socket)?
            };
            let proxy = async move {
                if let Err(e) = proxy(server_addr, cipher, &mut socket, original_dst_addr).await {
                    log::error!("failed to proxy; error={}", e);
                }
            };
            awak::spawn(proxy).detach();
        }
    }

    pub async fn packet_relay(&self) -> io::Result<()> {
        let cipher = Cipher::new(self.config.method, &self.config.password)?;
        let socket = listener::bind_udp(self.config.local_addr)?;
        log::info!("listening udp on {:?}", self.config.local_addr);
        let (sender, receiver) = channel(1024);
        let udp_relay = UdpRelay {
            buf: [0u8; MAX_UDP_BUFFER_SIZE],
            sender,
            receiver,
            socket,
            recv: None,
            cipher,
            server_addr: self.config.server_addr,
            redir_addr: self.config.redir_addr,
            sessions: Arc::new(Udp2022Sessions::new()),
        };
        udp_relay.await
    }
}

fn get_original_destination_addr(s: &TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();

    unsafe {
        let (_, addr) = SockAddr::try_init(|addr, addr_len| {
            match s.local_addr()? {
                SocketAddr::V4(..) => {
                    let ret = libc::getsockopt(
                        fd,
                        libc::SOL_IP,
                        libc::SO_ORIGINAL_DST,
                        addr as *mut _,
                        addr_len, // libc::socklen_t
                    );
                    if ret != 0 {
                        let err = io::Error::last_os_error();
                        return Err(err);
                    }
                }
                SocketAddr::V6(..) => {
                    let ret = libc::getsockopt(
                        fd,
                        libc::SOL_IPV6,
                        libc::IP6T_SO_ORIGINAL_DST,
                        addr as *mut _,
                        addr_len, // libc::socklen_t
                    );

                    if ret != 0 {
                        let err = io::Error::last_os_error();
                        return Err(err);
                    }
                }
            }
            Ok(())
        })?;
        addr.as_socket()
            .ok_or_else(|| io::Error::other("invalid SocketAddr"))
    }
}

struct UdpRelay {
    buf: [u8; MAX_UDP_BUFFER_SIZE],
    sender: Sender<(Vec<u8>, SocketAddr)>,
    receiver: Receiver<(Vec<u8>, SocketAddr)>,
    socket: UdpSocket,
    recv: Option<(Vec<u8>, SocketAddr)>,
    cipher: Cipher,
    server_addr: SocketAddr,
    redir_addr: Option<SocketAddr>,
    sessions: Arc<Udp2022Sessions>,
}

impl UdpRelay {
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
                    let server_addr = me.server_addr;
                    let redir_addr = me.redir_addr;
                    let sessions = Arc::clone(&me.sessions);
                    awak::spawn(async move {
                        if let Err(e) = proxy_packet(
                            server_addr,
                            cipher,
                            buf,
                            peer_addr,
                            redir_addr,
                            sender,
                            sessions,
                        )
                        .await
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
    server_addr: SocketAddr,
    mut cipher: Cipher,
    buf: Vec<u8>,
    peer_addr: SocketAddr,
    redir_addr: Option<SocketAddr>,
    mut sender: Sender<(Vec<u8>, SocketAddr)>,
    sessions: Arc<Udp2022Sessions>,
) -> io::Result<(u64, u64)> {
    let redir_addr = if let Some(redir_addr) = redir_addr {
        redir_addr
    } else {
        unimplemented!()
    };
    if cipher.is_aead2022() {
        return proxy_packet_2022(
            server_addr,
            cipher,
            buf,
            redir_addr,
            peer_addr,
            sender,
            sessions,
        )
        .await;
    }
    cipher.init_encrypt();
    let mut data = cipher.encrypt_prefix().to_vec();
    let rawaddr = generate_raw_addr(&redir_addr.ip().to_string(), redir_addr.port());
    data.extend_from_slice(&rawaddr);
    data.extend_from_slice(&buf);
    cipher.encrypt_in_place(&mut data[cipher.prefix_len()..])?;

    let local: SocketAddr = ([0u8; 4], 0).into();
    // send to and recv from target.
    let socket = UdpSocket::bind(local)?;
    socket.connect(server_addr)?;
    let _ = socket.send(&data).await?;
    let mut recv_buf = vec![0u8; MAX_UDP_BUFFER_SIZE];
    let n = socket.recv(&mut recv_buf).await?;
    recv_buf.truncate(n);

    // The server prefixes each UDP response with its own salt/IV.
    let salt_len = cipher.prefix_len();
    if n < salt_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp response shorter than salt",
        ));
    }
    cipher
        .decrypt_prefix_mut()
        .copy_from_slice(&recv_buf[..salt_len]);
    cipher.init_decrypt();
    recv_buf.drain(..salt_len);
    cipher.decrypt_in_place(&mut recv_buf)?;

    // Strip the SOCKS5 address prefix that the server's response body starts with.
    if let Some(atyp) = recv_buf.first().copied() {
        let skip = match atyp {
            TYPE_IPV4 => 1 + 4 + 2,
            TYPE_IPV6 => 1 + 16 + 2,
            TYPE_DOMAIN => 2 + recv_buf.get(1).copied().unwrap_or(0) as usize + 2,
            _ => 0,
        };
        if skip > 0 && recv_buf.len() >= skip {
            recv_buf.drain(..skip);
        }
    }
    sender
        .try_send((recv_buf.to_vec(), peer_addr))
        .map_err(|e| io::Error::other(format!("send fail: {e}")))?;
    Ok((buf.len() as u64, n as u64))
}

/// Relay a single AEAD-2022 (SIP022) UDP datagram to the server.
async fn proxy_packet_2022(
    server_addr: SocketAddr,
    cipher: Cipher,
    buf: Vec<u8>,
    redir_addr: SocketAddr,
    peer_addr: SocketAddr,
    mut sender: Sender<(Vec<u8>, SocketAddr)>,
    sessions: Arc<Udp2022Sessions>,
) -> io::Result<(u64, u64)> {
    let udp = Udp2022::new(cipher.method(), cipher.key())?;
    let (client_session_id, packet_id) = sessions.next_packet_id(peer_addr);
    let data = udp.encrypt_client_packet(
        client_session_id,
        packet_id,
        &redir_addr.ip().to_string(),
        redir_addr.port(),
        &buf,
    )?;

    // send to and recv from target.
    let local: SocketAddr = ([0u8; 4], 0).into();
    let socket = UdpSocket::bind(local)?;
    socket.connect(server_addr)?;
    let _ = socket.send(&data).await?;
    let mut recv_buf = vec![0u8; MAX_UDP_BUFFER_SIZE];
    let n = socket.recv(&mut recv_buf).await?;
    recv_buf.truncate(n);

    let response = udp.decrypt_server_packet(&recv_buf)?;
    if response.client_session_id != client_session_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "2022 udp response belongs to another session",
        ));
    }
    if !sessions.accept_response(peer_addr, response.packet_id, response.server_session_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "replayed 2022 udp response, packet id {}",
                response.packet_id
            ),
        ));
    }

    sender
        .try_send((response.payload, peer_addr))
        .map_err(|e| io::Error::other(format!("send fail: {e}")))?;
    Ok((buf.len() as u64, n as u64))
}

async fn proxy<A>(
    server_addr: SocketAddr,
    cipher: Cipher,
    socket1: &mut A,
    original_dst_addr: SocketAddr,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut socket2 = timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect(&server_addr)).await??;
    log::debug!("connected to server {}", server_addr);

    let is_aead2022 = cipher.is_aead2022();

    let mut socket2 = CipherStream::local(cipher, &mut socket2);

    let mut rawaddr = generate_raw_addr(
        &original_dst_addr.ip().to_string(),
        original_dst_addr.port(),
    );
    if is_aead2022 {
        let padding = BytesMut::zeroed(16);
        rawaddr.extend_from_slice(&u16::to_be_bytes(padding.len() as u16));
        rawaddr.extend_from_slice(&padding);
    }
    socket2.write_all(&rawaddr).await?;

    let (n1, n2) = IdleTimeout::new(
        copy_bidirectional(socket1, &mut socket2),
        DEFAULT_IDLE_TIMEOUT,
        DEFAULT_CHECK_INTERVAL,
    )
    .await??;
    log::debug!("proxy local => remote: {}, remote => local: {:?}", n1, n2);
    Ok((n1, n2))
}
