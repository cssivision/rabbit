#![allow(clippy::many_single_char_names)]
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use awak::net::{TcpStream, UdpSocket};
use awak::time::{interval, timeout};
use awak::util::{IdleTimeout, copy_bidirectional_with_buffer_size};
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, Stream, StreamExt, future::join};

use crate::CipherStream;
use crate::cipher::Cipher;
use crate::config::{self, Addr, Transport};
use crate::listener::{self, Listener};
use crate::resolver::resolve;
use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};
use crate::udp_legacy;
use crate::udp2022::{PacketWindow, Udp2022};
use crate::util::COPY_BUFFER_SIZE;
use crate::{DEFAULT_CHECK_INTERVAL, DEFAULT_IDLE_TIMEOUT};

const DEFAULT_GET_ADDR_INFO_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_RESLOVE_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UDP_BUFFER_SIZE: usize = 65536;
/// How long an AEAD-2022 UDP session (and its server session id / packet
/// counter) is kept alive after the last packet.
const DEFAULT_UDP2022_SESSION_TIMEOUT: Duration = Duration::from_secs(300);
/// How long an idle outbound UDP flow keeps its socket.
const DEFAULT_UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_UDP_NAT_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// How often idle flows and sessions are reaped even when no traffic arrives.
const DEFAULT_UDP_REAPER_INTERVAL: Duration = Duration::from_secs(30);

/// Per client-session state for AEAD-2022 UDP.
///
/// SIP022 derives the server -> client key from a *server* session id and seals
/// every response with an increasing packet id, so the server has to remember
/// both for the lifetime of the session.
struct Udp2022Sessions {
    inner: Mutex<Udp2022SessionsInner>,
}

struct Udp2022SessionsInner {
    sessions: HashMap<u64, Udp2022Session>,
    last_sweep: Instant,
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
            inner: Mutex::new(Udp2022SessionsInner {
                sessions: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Drop sessions that have been idle for longer than the timeout. Called by
    /// the reaper so state does not pile up while the relay is quiet.
    fn reap(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.sweep(Instant::now());
    }

    /// Look up (or create) the session for `client_session_id` and check the
    /// packet id against the replay window. Returns `false` for replays.
    fn accept(&self, client_session_id: u64, packet_id: u64) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        inner.sweep_if_due(now);
        let sessions = &mut inner.sessions;

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
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        inner.sweep_if_due(now);
        let sessions = &mut inner.sessions;

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

impl Udp2022SessionsInner {
    fn sweep(&mut self, now: Instant) {
        self.sessions
            .retain(|_, s| now.duration_since(s.last_seen) < DEFAULT_UDP2022_SESSION_TIMEOUT);
        self.last_sweep = now;
    }

    fn sweep_if_due(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) >= DEFAULT_UDP_NAT_SWEEP_INTERVAL {
            self.sweep(now);
        }
    }
}

fn random_session_id() -> u64 {
    let mut buf = [0u8; 8];
    rand::fill(&mut buf[..]);
    let id = u64::from_be_bytes(buf);
    if id == 0 { 1 } else { id }
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
        match self.config.transport {
            Transport::Stream => self.stream_relay().await,
            Transport::Packet => self.packet_relay().await,
            Transport::Both => {
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

/// Key identifying one outbound flow: client address, destination and, for
/// SIP022, the client session id.
type UdpKey = (SocketAddr, String, u16, u64);

struct UdpEntry {
    sender: UnboundedSender<Vec<u8>>,
    last_seen: Instant,
}

struct UdpNatState {
    entries: HashMap<UdpKey, UdpEntry>,
    last_sweep: Instant,
}

/// Reusable outbound sockets, one per client/destination flow.
///
/// Binding a socket and spawning a task for every datagram made the relay
/// drop packets under load, so a flow is created once and then reused until
/// it has been idle for `DEFAULT_UDP_FLOW_TIMEOUT`.
struct UdpNat {
    state: Mutex<UdpNatState>,
}

impl UdpNatState {
    fn sweep(&mut self, now: Instant) {
        self.entries
            .retain(|_, e| now.duration_since(e.last_seen) < DEFAULT_UDP_FLOW_TIMEOUT);
        self.last_sweep = now;
    }

    fn sweep_if_due(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) >= DEFAULT_UDP_NAT_SWEEP_INTERVAL {
            self.sweep(now);
        }
    }
}

impl UdpNat {
    fn new() -> UdpNat {
        UdpNat {
            state: Mutex::new(UdpNatState {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Drop flows that have been idle for longer than the timeout. Dropping
    /// the entry closes the flow channel, which ends the flow task and frees
    /// its socket.
    fn reap(&self) {
        let mut state = self.state.lock().unwrap();
        state.sweep(Instant::now());
    }

    /// Hand `payload` to the flow for `key`, creating the flow on first use.
    fn dispatch(
        &self,
        key: UdpKey,
        mut payload: Vec<u8>,
        cipher: &Cipher,
        sender: &UnboundedSender<(Vec<u8>, SocketAddr)>,
        sessions: &Arc<Udp2022Sessions>,
    ) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        state.sweep_if_due(now);

        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_seen = now;
            match entry.sender.unbounded_send(payload) {
                Ok(()) => return,
                Err(e) => {
                    // The flow task is gone; drop the entry so the packet
                    // below starts a fresh one.
                    payload = e.into_inner();
                }
            }
            state.entries.remove(&key);
        }

        let (tx, rx) = unbounded();
        if tx.unbounded_send(payload).is_err() {
            return;
        }
        state.entries.insert(
            key.clone(),
            UdpEntry {
                sender: tx,
                last_seen: now,
            },
        );
        awak::spawn(udp_flow(
            key,
            rx,
            cipher.reset(),
            sender.clone(),
            Arc::clone(sessions),
        ))
        .detach();
    }
}

/// One outbound flow: forwards client payloads to the destination and relays
/// the replies back through the relay's response channel.
async fn udp_flow(
    key: UdpKey,
    mut packets: UnboundedReceiver<Vec<u8>>,
    cipher: Cipher,
    sender: UnboundedSender<(Vec<u8>, SocketAddr)>,
    sessions: Arc<Udp2022Sessions>,
) -> io::Result<()> {
    let (client, host, port, client_session_id) = key.clone();
    let addr = timeout(DEFAULT_RESLOVE_TIMEOUT, resolve(&host)).await??;
    let local: SocketAddr = if addr.is_ipv4() {
        ([0u8; 4], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };

    let socket = Arc::new(UdpSocket::bind(local)?);
    listener::tune_udp_socket(&socket);
    socket.connect((addr, port))?;
    log::debug!("udp flow {:?} -> {}:{}", client, host, port);

    let replies = udp_reply_loop(
        Arc::clone(&socket),
        SocketAddr::new(addr, port),
        client,
        client_session_id,
        cipher,
        sender,
        sessions,
    );
    let requests = udp_request_loop(socket, &mut packets);
    let ((), ()) = join(replies, requests).await;
    Ok(())
}

async fn udp_request_loop(socket: Arc<UdpSocket>, packets: &mut UnboundedReceiver<Vec<u8>>) {
    while let Some(payload) = packets.next().await {
        if let Err(e) = socket.send(&payload).await {
            log::error!("udp flow send failed: {}", e);
            return;
        }
    }
}

async fn udp_reply_loop(
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    client: SocketAddr,
    client_session_id: u64,
    cipher: Cipher,
    sender: UnboundedSender<(Vec<u8>, SocketAddr)>,
    sessions: Arc<Udp2022Sessions>,
) {
    let udp2022 = if cipher.is_aead2022() {
        match Udp2022::new(cipher.method(), cipher.key()) {
            Ok(udp) => Some(udp),
            Err(e) => {
                log::error!("udp flow: {}", e);
                return;
            }
        }
    } else {
        None
    };

    let mut recv_buf = vec![0u8; MAX_UDP_BUFFER_SIZE];
    loop {
        let (n, src) =
            match timeout(DEFAULT_UDP_FLOW_TIMEOUT, socket.recv_from(&mut recv_buf)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    log::error!("udp flow recv failed: {}", e);
                    return;
                }
                Err(_) => {
                    log::debug!("udp flow {:?} idle, closing", client);
                    return;
                }
            };

        let data = match &udp2022 {
            Some(udp) => {
                let (server_session_id, packet_id) = sessions.next(client_session_id);
                match udp.encrypt_server_packet(
                    server_session_id,
                    packet_id,
                    client_session_id,
                    &src.ip().to_string(),
                    src.port(),
                    &recv_buf[..n],
                ) {
                    Ok(data) => data,
                    Err(e) => {
                        log::error!("udp flow encrypt failed: {}", e);
                        return;
                    }
                }
            }
            None => {
                match udp_legacy::seal(
                    &cipher,
                    &target.ip().to_string(),
                    target.port(),
                    &recv_buf[..n],
                ) {
                    Ok(data) => data,
                    Err(e) => {
                        log::error!("udp flow encrypt failed: {}", e);
                        return;
                    }
                }
            }
        };

        if sender.unbounded_send((data, client)).is_err() {
            log::warn!("udp reply to {:?} dropped: relay closed", client);
            return;
        }
    }
}

struct UdpRelay {
    buf: [u8; MAX_UDP_BUFFER_SIZE],
    sender: UnboundedSender<(Vec<u8>, SocketAddr)>,
    receiver: UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    socket: UdpSocket,
    recv: Option<(Vec<u8>, SocketAddr)>,
    cipher: Cipher,
    sessions: Arc<Udp2022Sessions>,
    nat: Arc<UdpNat>,
}

impl UdpRelay {
    fn new(socket: UdpSocket, cipher: Cipher) -> UdpRelay {
        let (sender, receiver) = unbounded();
        let sessions = Arc::new(Udp2022Sessions::new());
        let nat = Arc::new(UdpNat::new());

        // Reap idle flows and sessions on a timer: waiting for the next packet
        // would keep sockets and replay windows alive forever on a quiet relay.
        let reaper_nat = Arc::clone(&nat);
        let reaper_sessions = Arc::clone(&sessions);
        awak::spawn(async move {
            let mut ticker = interval(DEFAULT_UDP_REAPER_INTERVAL);
            loop {
                ticker.tick().await;
                reaper_nat.reap();
                reaper_sessions.reap();
            }
        })
        .detach();

        UdpRelay {
            buf: [0u8; MAX_UDP_BUFFER_SIZE],
            sender,
            receiver,
            socket,
            recv: None,
            cipher,
            sessions,
            nat,
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
                    let buf = me.buf[..n].to_vec();
                    let mut cipher = me.cipher.reset();
                    let decoded = if cipher.is_aead2022() {
                        decode_2022(&cipher, &buf, &me.sessions)
                    } else {
                        decode_legacy(&mut cipher, &buf)
                    };
                    match decoded {
                        Ok((host, port, session, payload)) => {
                            let key: UdpKey = (peer_addr, host, port, session);
                            me.nat
                                .dispatch(key, payload, &me.cipher, &me.sender, &me.sessions);
                        }
                        Err(e) => log::warn!("udp packet from {:?} dropped: {}", peer_addr, e),
                    }
                }
            }
        }
    }
}

/// Decrypt a legacy (pre-SIP022) datagram and return its destination.
fn decode_legacy(cipher: &mut Cipher, buf: &[u8]) -> io::Result<(String, u16, u64, Vec<u8>)> {
    let (host, port, payload) = udp_legacy::open(cipher, buf)?;
    Ok((host, port, 0, payload))
}

/// Decrypt a SIP022 datagram and check its packet id for replays.
fn decode_2022(
    cipher: &Cipher,
    buf: &[u8],
    sessions: &Udp2022Sessions,
) -> io::Result<(String, u16, u64, Vec<u8>)> {
    let udp = Udp2022::new(cipher.method(), cipher.key())?;
    let request = udp.decrypt_client_packet(buf)?;
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
    Ok((
        request.host,
        request.port,
        request.client_session_id,
        request.payload,
    ))
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
        copy_bidirectional_with_buffer_size(&mut socket2, socket1, COPY_BUFFER_SIZE),
        DEFAULT_IDLE_TIMEOUT,
        DEFAULT_CHECK_INTERVAL,
    )
    .await
    .map_err(|e| io::Error::other(format!("idle timeout: {e:?}")))?
    .map_err(|e| io::Error::other(format!("copy bidirectional fail: {e:?}")))?;
    log::debug!("proxy local => remote: {}, remote => local: {}", n1, n2);
    Ok((n1, n2))
}

/// Parse a SOCKS5 address at the start of `buf`, returning its length, host and
/// port.
fn parse_socks_addr(buf: &[u8]) -> io::Result<(usize, String, u16)> {
    udp_legacy::parse_address(buf)
}

async fn get_addr_info<A>(conn: &mut A) -> io::Result<(usize, String, u16)>
where
    A: AsyncRead + Unpin + ?Sized,
{
    let address_type = &mut [0u8; 1];
    conn.read_exact(address_type).await?;
    // `rest` counts the bytes still to read after the address type. For a
    // domain the length byte is part of the address, so it is read separately
    // and put back into `buf` below instead of being counted here.
    let (rest, domain_len) = match address_type[0] {
        TYPE_IPV4 => (6, None),
        TYPE_IPV6 => (18, None),
        TYPE_DOMAIN => {
            let len = &mut [0u8; 1];
            conn.read_exact(len).await?;
            // The length byte is already consumed, but `buf` still needs a slot
            // for it so the address can be parsed as `[len][name][port]`.
            (1 + len[0] as usize + 2, Some(len[0]))
        }
        n => {
            log::error!("unknown address type, received: {:?}", n);
            return Err(io::Error::other("unknown address type, received"));
        }
    };

    let mut buf = vec![0u8; 1 + rest];
    buf[0] = address_type[0];
    // A domain address is `[len][name][port]`; the length byte has already been
    // consumed, so write it back and read only the name and port.
    let offset = match domain_len {
        Some(len) => {
            buf[1] = len;
            2
        }
        None => 1,
    };
    conn.read_exact(&mut buf[offset..]).await?;
    parse_socks_addr(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> UdpKey {
        (
            "127.0.0.1:1234".parse().unwrap(),
            "example.com".to_string(),
            443,
            0,
        )
    }

    fn expired() -> Instant {
        Instant::now() - DEFAULT_UDP_FLOW_TIMEOUT - Duration::from_secs(1)
    }

    #[test]
    fn reaper_drops_idle_flows() {
        let nat = UdpNat::new();
        let (tx, _rx) = unbounded();
        {
            let mut state = nat.state.lock().unwrap();
            state.entries.insert(
                key(),
                UdpEntry {
                    sender: tx,
                    last_seen: expired(),
                },
            );
        }

        nat.reap();

        assert!(nat.state.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn reaper_keeps_active_flows() {
        let nat = UdpNat::new();
        let (tx, _rx) = unbounded();
        nat.state.lock().unwrap().entries.insert(
            key(),
            UdpEntry {
                sender: tx,
                last_seen: Instant::now(),
            },
        );

        nat.reap();

        assert_eq!(nat.state.lock().unwrap().entries.len(), 1);
    }

    #[test]
    fn reaper_drops_idle_sessions() {
        let sessions = Udp2022Sessions::new();
        assert!(sessions.accept(7, 1));
        {
            let mut inner = sessions.inner.lock().unwrap();
            inner.sessions.get_mut(&7).unwrap().last_seen = expired();
        }

        sessions.reap();

        assert!(sessions.inner.lock().unwrap().sessions.is_empty());
        // A later packet from the same client starts a fresh session.
        assert!(sessions.accept(7, 1));
    }

    #[test]
    fn session_sweep_keeps_recent_packets_filtered() {
        let sessions = Udp2022Sessions::new();
        assert!(sessions.accept(1, 1));
        assert!(!sessions.accept(1, 1));
        sessions.reap();
        assert!(!sessions.accept(1, 1), "replay must stay rejected");
    }
}
