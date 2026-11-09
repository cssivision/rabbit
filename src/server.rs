#![allow(clippy::many_single_char_names)]
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use awak::net::{TcpStream, UdpSocket};
use awak::time::timeout;
use awak::util::{IdleTimeout, copy_bidirectional_with_buffer_size};
use bytes::Bytes;
use futures_channel::mpsc::{Receiver, Sender, channel};
use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, Stream, future::join};
use lru_time_cache::LruCache;

use crate::CipherStream;
use crate::cipher::Cipher;
use crate::config::{self, Addr, Transport};
use crate::listener::{self, Listener};
use crate::resolver::resolve;
use crate::udp_legacy;
use crate::udp2022::{PacketWindow, Udp2022};
use crate::util::{COPY_BUFFER_SIZE, random_session_id, read_address};
use crate::{DEFAULT_CHECK_INTERVAL, DEFAULT_IDLE_TIMEOUT};

const DEFAULT_READ_ADDRESS_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_RESLOVE_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UDP_BUFFER_SIZE: usize = 65536;
/// How long an AEAD-2022 UDP session (and its server session id / packet
/// counter) is kept alive after the last packet.
const DEFAULT_UDP2022_SESSION_TIMEOUT: Duration = Duration::from_secs(300);
/// How long an idle outbound UDP flow keeps its socket.
const DEFAULT_UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(300);
/// Upper bound on concurrent outbound flows for one UDP listener.
///
/// A forged source address creates a flow on first use, so the table needs a
/// hard limit: without one a flood of spoofed datagrams allocates a socket and
/// a task per packet.
const MAX_UDP_FLOWS: usize = 2048;
/// Upper bound on remembered AEAD-2022 sessions for one listener.
const MAX_UDP2022_SESSIONS: usize = 2048;
/// How many outbound packets one flow may have queued before the relay drops
/// new ones.
///
/// The queue feeds `udp_request_loop`, so it bounds how far a slow destination
/// can lag behind a fast client. UDP tolerates loss, and an unbounded queue
/// would grow until the process is killed.
const UDP_FLOW_QUEUE: usize = 1024;

/// Per client-session state for AEAD-2022 UDP.
///
/// SIP022 derives the server -> client key from a *server* session id and seals
/// every response with an increasing packet id, so the server has to remember
/// both for the lifetime of the session.
///
/// Like the flow table this is an `LruCache`, so both the idle timeout and the
/// entry count are bounded without a background sweep: every `accept`/`next`
/// call prunes expired sessions, which is enough because a session is only
/// reachable through a packet.
struct Udp2022Sessions {
    inner: Mutex<LruCache<u64, Udp2022Session>>,
}

struct Udp2022Session {
    server_session_id: u64,
    next_packet_id: u64,
    window: PacketWindow,
}

impl Udp2022Sessions {
    fn new() -> Udp2022Sessions {
        Udp2022Sessions {
            inner: Mutex::new(LruCache::with_expiry_duration_and_capacity(
                DEFAULT_UDP2022_SESSION_TIMEOUT,
                MAX_UDP2022_SESSIONS,
            )),
        }
    }

    /// Look up (or create) the session for `client_session_id` and check the
    /// packet id against the replay window. Returns `false` for replays.
    fn accept(&self, client_session_id: u64, packet_id: u64) -> bool {
        let mut sessions = self.inner.lock().unwrap();
        let session = sessions
            .entry(client_session_id)
            .or_insert_with(|| Udp2022Session {
                server_session_id: random_session_id(),
                next_packet_id: 1,
                window: PacketWindow::new(),
            });
        session.window.validate(packet_id)
    }

    /// Allocate the `(server_session_id, packet_id)` pair for the next
    /// response. The packet id is incremented before use, so the first
    /// response carries 1.
    fn next(&self, client_session_id: u64) -> (u64, u64) {
        let mut sessions = self.inner.lock().unwrap();
        let session = sessions
            .entry(client_session_id)
            .or_insert_with(|| Udp2022Session {
                server_session_id: random_session_id(),
                next_packet_id: 1,
                window: PacketWindow::new(),
            });

        let packet_id = session.next_packet_id;
        session.next_packet_id = session.next_packet_id.wrapping_add(1);
        (session.server_session_id, packet_id)
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
        UdpRelay::new(socket, cipher)?.await
    }
}

/// Key identifying one outbound flow: client address, destination and, for
/// SIP022, the client session id.
type UdpKey = (SocketAddr, String, u16, u64);

struct UdpEntry {
    sender: Sender<Bytes>,
}

/// Seals a datagram the destination sent into one the client can decrypt.
///
/// The reply half of the relay's wire codec: `UdpRelay::decode_legacy` and
/// `decode_2022` are the mirror-image request half. It owns everything that
/// direction needs, which is why it is one type rather than five fields spread
/// over `UdpFlow`: only one method ever reads them.
struct UdpReplyCodec {
    /// Legacy headers name the destination the client asked for, while SIP022
    /// headers name the source the reply actually came from. This is the former.
    target_addr: SocketAddr,
    client_session_id: u64,
    cipher: Cipher,
    /// Present only for the 2022 methods. Its own codec, sharing the relay's
    /// session table so packet ids stay in one sequence.
    udp2022: Option<Udp2022>,
    sessions: Arc<Udp2022Sessions>,
}

impl UdpReplyCodec {
    fn new(
        target_addr: SocketAddr,
        client_session_id: u64,
        cipher: Cipher,
        sessions: Arc<Udp2022Sessions>,
    ) -> io::Result<UdpReplyCodec> {
        let udp2022 = Udp2022::from_cipher(&cipher)?;
        Ok(UdpReplyCodec {
            target_addr,
            client_session_id,
            cipher,
            udp2022,
            sessions,
        })
    }

    fn seal(&mut self, src: SocketAddr, payload: &[u8]) -> io::Result<Bytes> {
        match &mut self.udp2022 {
            Some(udp) => {
                let (server_session_id, packet_id) = self.sessions.next(self.client_session_id);
                udp.encrypt_server_packet(
                    server_session_id,
                    packet_id,
                    self.client_session_id,
                    &src.ip().to_string(),
                    src.port(),
                    payload,
                )
            }
            None => udp_legacy::seal(
                &self.cipher,
                &self.target_addr.ip().to_string(),
                self.target_addr.port(),
                payload,
            ),
        }
    }
}

/// The two sockets one flow talks through, each named after the peer it faces.
///
/// They are not symmetric: `target` belongs to this flow alone and is connected
/// to the destination, while `client` is a clone of the relay's listener socket
/// that every flow shares. Sharing it lets flows answer concurrently, which the
/// kernel allows for `send_to` on the same socket, instead of funnelling replies
/// through a channel to the relay's single task.
struct DatagramLink {
    /// Connected to the destination: requests are written here and replies are
    /// read here. Owned outright: no other task ever touches this socket, so it
    /// needs no reference count.
    target: UdpSocket,
    /// The relay's listening socket, used only to send replies. Shared with the
    /// relay and with every other flow, hence the `Arc`.
    client: Arc<UdpSocket>,
    /// The client this flow answers, i.e. the `send_to` peer of every reply.
    client_addr: SocketAddr,
}

impl DatagramLink {
    /// Bind a socket of the destination's family and connect it to `target`.
    fn connect(
        target: SocketAddr,
        client: Arc<UdpSocket>,
        client_addr: SocketAddr,
    ) -> io::Result<DatagramLink> {
        // Match the family of the resolved destination so the socket can reach it.
        let bind_addr: SocketAddr = if target.is_ipv4() {
            ([0u8; 4], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let socket = UdpSocket::bind(bind_addr)?;
        listener::tune_udp_socket(&socket);
        socket.connect(target)?;
        Ok(DatagramLink {
            target: socket,
            client,
            client_addr,
        })
    }

    /// One reply from the destination, written into `buf`.
    fn poll_recv_reply(
        &self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.target.poll_recv_from(cx, buf)
    }

    /// Push one client datagram to the destination.
    ///
    /// `ready!` and `?` keep the two outcomes apart: a `Pending` send leaves the
    /// datagram in `pending_send` for the next round, an error ends the flow. The
    /// byte count is dropped because a datagram is written whole or not at all.
    fn poll_send_request(&self, cx: &Context<'_>, data: &[u8]) -> Poll<io::Result<()>> {
        ready!(self.target.poll_send(cx, data))?;
        Poll::Ready(Ok(()))
    }

    /// Push one sealed reply back to the client.
    ///
    /// Takes the payload by reference because `pending_reply` owns it: a
    /// `Pending` return has to leave it in place for the retry at the top of the
    /// loop.
    fn poll_send_reply(&self, cx: &Context<'_>, data: &[u8]) -> Poll<io::Result<()>> {
        ready!(self.client.poll_send_to(cx, data, self.client_addr))?;
        Poll::Ready(Ok(()))
    }
}

/// One outbound flow: relays datagrams between one client and one destination.
///
/// Polling the flow drives both directions at once: datagrams queued for it go
/// out `link` to the destination, and datagrams coming back are sealed by
/// `codec` and sent back through the same link. The flow ends when either
/// direction does.
struct UdpFlow {
    link: DatagramLink,
    /// Datagrams queued by the relay, one entry per client datagram.
    packets: Receiver<Bytes>,
    codec: UdpReplyCodec,
    /// Receive buffer for datagrams coming back from the destination.
    recv_buf: Vec<u8>,
    /// A datagram taken from `packets` that the target has not accepted yet.
    pending_send: Option<Bytes>,
    /// A reply that the client socket has not accepted yet.
    pending_reply: Option<Bytes>,
}

impl UdpFlow {
    /// Resolve the destination and open the flow socket.
    async fn connect(
        key: UdpKey,
        packets: Receiver<Bytes>,
        cipher: Cipher,
        client_socket: Arc<UdpSocket>,
        sessions: Arc<Udp2022Sessions>,
    ) -> io::Result<UdpFlow> {
        let (client, host, port, client_session_id) = key;
        let addr = timeout(DEFAULT_RESLOVE_TIMEOUT, resolve(&host)).await??;
        let target_addr = SocketAddr::new(addr, port);

        let link = DatagramLink::connect(target_addr, client_socket, client)?;
        log::debug!("udp flow {:?} -> {}:{}", client, host, port);

        Ok(UdpFlow {
            link,
            packets,
            codec: UdpReplyCodec::new(target_addr, client_session_id, cipher, sessions)?,
            recv_buf: vec![0u8; MAX_UDP_BUFFER_SIZE],
            pending_send: None,
            pending_reply: None,
        })
    }
}

impl Future for UdpFlow {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Every field is `Unpin`, so the flow can be taken apart without unsafe.
        let me = self.get_mut();

        loop {
            // Datagrams a full send buffer turned away last round are retried
            // first, so a ready socket can never starve them. `pending_reply`
            // has to go out before the destination is read again anyway: it is a
            // single slot, and a second reply would replace the one still waiting
            // for the client socket.
            if let Some(data) = &me.pending_reply {
                ready!(me.link.poll_send_reply(cx, data))?;
                me.pending_reply = None;
            }
            if let Some(data) = &me.pending_send {
                ready!(me.link.poll_send_request(cx, data))?;
                me.pending_send = None;
            }

            // The destination drives the loop: one reply per round. While it is
            // quiet the `Pending` arm below does everything else, so a busy
            // client cannot starve the reply path.
            match me.link.poll_recv_reply(cx, &mut me.recv_buf) {
                Poll::Ready(res) => {
                    let (n, src) = res?;
                    me.pending_reply = Some(me.codec.seal(src, &me.recv_buf[..n])?);
                }
                Poll::Pending => {
                    // One datagram from the client's queue per round, sent on
                    // the next round after the flush above. Taking it and
                    // looping is what replaces a drain loop here: the outer loop
                    // keeps pulling until the queue is empty, and a send that
                    // would block parks the payload in `pending_send`.
                    if let Poll::Ready(packet) = Pin::new(&mut me.packets).poll_next(cx) {
                        let Some(payload) = packet else {
                            // The client's queue closed: the NAT table dropped
                            // the entry.
                            return Poll::Ready(Ok(()));
                        };
                        me.pending_send = Some(payload);
                        continue;
                    }

                    // Every waker is registered: nothing to do until the client
                    // sends, the destination answers, or `IdleTimeout` gives up.
                    return Poll::Pending;
                }
            }
        }
    }
}

struct UdpRelay {
    buf: [u8; MAX_UDP_BUFFER_SIZE],
    socket: Arc<UdpSocket>,
    cipher: Cipher,
    /// SIP022 codec for this listener, or `None` for the other methods.
    ///
    /// Kept here rather than rebuilt per packet so its per-session subkey cache
    /// is reused.
    udp2022: Option<Udp2022>,
    /// Per client-session packet counters and replay windows, shared with every
    /// flow so replies continue the request's packet id sequence.
    sessions: Arc<Udp2022Sessions>,
    /// Outbound flows, keyed by client/destination.
    ///
    /// `LruCache` bounds the table two ways at once: an entry expires once it
    /// has been unused for `DEFAULT_UDP_FLOW_TIMEOUT`, and the least recently
    /// used entry is dropped when the table is at `MAX_UDP_FLOWS`. That matters
    /// because a forged source address creates a flow on first use, so without a
    /// hard bound a flood of spoofed datagrams allocates a socket and a task per
    /// packet. Evicting the oldest flow beats dropping the new packet: the new
    /// one belongs to a client that is actively sending.
    ///
    /// A plain field rather than a lock: only `poll` touches it, and that runs
    /// on one task.
    flows: LruCache<UdpKey, UdpEntry>,
}

impl UdpRelay {
    fn new(socket: UdpSocket, cipher: Cipher) -> io::Result<UdpRelay> {
        // Both tables are LruCaches, so they prune themselves on access: there
        // is no background sweep. A flow's socket is freed by its own reply
        // loop timing out, and a session is unreachable without a packet.
        let sessions = Arc::new(Udp2022Sessions::new());
        let udp2022 = Udp2022::from_cipher(&cipher)?;

        Ok(UdpRelay {
            buf: [0u8; MAX_UDP_BUFFER_SIZE],
            socket: Arc::new(socket),
            cipher,
            udp2022,
            sessions,
            flows: LruCache::with_expiry_duration_and_capacity(
                DEFAULT_UDP_FLOW_TIMEOUT,
                MAX_UDP_FLOWS,
            ),
        })
    }

    /// Hand `payload` to the flow for `key`, creating the flow on first use.
    fn dispatch(&mut self, key: UdpKey, mut payload: Bytes) {
        if let Some(entry) = self.flows.get_mut(&key) {
            match entry.sender.try_send(payload) {
                Ok(()) => return,
                // Full queue: the flow cannot keep up. Dropping is the correct
                // behaviour for UDP, and the flow stays as it is.
                Err(e) if e.is_full() => return,
                // Closed channel: the flow task is gone, so replace the entry.
                Err(e) => payload = e.into_inner(),
            }
            self.flows.remove(&key);
        }

        let (mut tx, rx) = channel(UDP_FLOW_QUEUE);
        if tx.try_send(payload).is_err() {
            return;
        }
        // Inserting may evict the least recently used flow if the table is full.
        self.flows.insert(key.clone(), UdpEntry { sender: tx });

        let cipher = self.cipher.reset();
        // Every flow sends its replies through a clone of this same socket.
        let client_socket = Arc::clone(&self.socket);
        let sessions = Arc::clone(&self.sessions);
        awak::spawn(async move {
            // Starting the flow can fail (resolve, bind, connect) and so can
            // polling it once running; both end the flow, so report them alike.
            // The flow itself has no notion of time: `IdleTimeout` gives up when
            // the whole thing makes no progress for one timeout period, which
            // covers a quiet client and a quiet destination alike.
            let result = match UdpFlow::connect(key, rx, cipher, client_socket, sessions).await {
                Ok(flow) => {
                    // `IdleTimeout` reports its own timeout as the outer error, so
                    // `and_then` flattens the two layers back into one.
                    IdleTimeout::new(flow, DEFAULT_UDP_FLOW_TIMEOUT, DEFAULT_CHECK_INTERVAL)
                        .await
                        .and_then(|inner| inner)
                }
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                log::debug!("udp flow ended: {}", e);
            }
        })
        .detach();
    }
    /// Decrypt the datagram of `len` bytes at the front of the receive buffer.
    ///
    /// Legacy datagrams carry their own seed, so a throwaway `Cipher` is used
    /// rather than keeping per-datagram state on the relay.
    fn decode_legacy(&self, len: usize) -> io::Result<(String, u16, u64, Bytes)> {
        let mut cipher = self.cipher.reset();
        let (host, port, payload) = udp_legacy::open(&mut cipher, &self.buf[..len])?;
        Ok((host, port, 0, payload))
    }

    /// Decrypt a SIP022 datagram and check its packet id for replays.
    ///
    /// `udp2022` lives on the relay so its per-session subkey cache survives
    /// across packets.
    fn decode_2022(&mut self, len: usize) -> io::Result<(String, u16, u64, Bytes)> {
        // `buf` and `udp2022` are disjoint fields, so borrowing one while
        // mutating the other is fine.
        let UdpRelay {
            buf,
            udp2022,
            sessions,
            ..
        } = self;
        let udp = udp2022
            .as_mut()
            .expect("decode_2022 is only called for SIP022 methods");

        let request = udp.decrypt_client_packet(&buf[..len])?;
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
}

impl Future for UdpRelay {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            // Replies do not pass through here: each flow sends its own from its
            // own task, so this waits only on the next inbound datagram.
            let (n, peer_addr) = ready!(me.socket.poll_recv_from(cx, &mut me.buf))?;
            log::debug!("recv {} byte from {:?}", n, peer_addr);

            let decoded = if me.udp2022.is_some() {
                me.decode_2022(n)
            } else {
                me.decode_legacy(n)
            };
            match decoded {
                Ok((host, port, session, payload)) => {
                    let key: UdpKey = (peer_addr, host, port, session);
                    me.dispatch(key, payload);
                }
                Err(e) => log::error!("udp packet from {:?} dropped: {}", peer_addr, e),
            }
        }
    }
}

async fn proxy<A>(cipher: Cipher, socket1: &mut A) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let is_aead2022 = cipher.is_aead2022();
    let socket1 = &mut CipherStream::remote(cipher, socket1);
    let (_, host, port) = timeout(DEFAULT_READ_ADDRESS_TIMEOUT, read_address(socket1))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key_of(n: u16) -> UdpKey {
        (
            SocketAddr::from(([127, 0, 0, 1], 1000 + n)),
            "example.com".to_string(),
            443,
            0,
        )
    }

    /// The table must not grow past its cap; the least recently used flow is
    /// evicted, not the newest packet dropped.
    #[test]
    fn nat_evicts_least_recently_used_flow() {
        let mut flows: LruCache<UdpKey, UdpEntry> =
            LruCache::with_expiry_duration_and_capacity(DEFAULT_UDP_FLOW_TIMEOUT, 4);

        for i in 0..4u16 {
            let (tx, _rx) = channel(1);
            flows.insert(key_of(i), UdpEntry { sender: tx });
        }
        assert_eq!(flows.len(), 4);

        // Touch flow 0 so it stops being the least recently used, then add a
        // fifth flow: flow 1 is now the oldest and must be the one evicted.
        assert!(flows.get(&key_of(0)).is_some());
        let (tx, _rx) = channel(1);
        flows.insert(key_of(9), UdpEntry { sender: tx });

        assert_eq!(flows.len(), 4, "table grew past its cap");
        assert!(flows.get(&key_of(9)).is_some(), "new flow missing");
        assert!(flows.get(&key_of(0)).is_some(), "recent flow evicted");
        assert!(flows.get(&key_of(1)).is_none(), "LRU flow kept");
    }

    /// A session that is still fresh must survive the pruning that happens on
    /// every access.
    #[test]
    fn sessions_keep_fresh_entries() {
        let sessions = Udp2022Sessions::new();
        assert!(sessions.accept(7, 1));

        // Touch the table again; the entry is not old enough to expire.
        assert!(sessions.accept(8, 1));

        assert_eq!(sessions.inner.lock().unwrap().len(), 2);
    }

    /// The session table is bounded, and the least recently used session is the
    /// one evicted — the same rule as the flow table.
    #[test]
    fn sessions_evict_least_recently_used() {
        let sessions = Udp2022Sessions::new();
        *sessions.inner.lock().unwrap() =
            LruCache::with_expiry_duration_and_capacity(DEFAULT_UDP2022_SESSION_TIMEOUT, 4);

        for id in 0..4u64 {
            assert!(sessions.accept(id, 1));
        }
        assert_eq!(sessions.inner.lock().unwrap().len(), 4);

        // Touch session 0 so it stops being the oldest, then add a fifth.
        assert!(sessions.accept(0, 2));
        assert!(sessions.accept(9, 1));

        let mut inner = sessions.inner.lock().unwrap();
        assert_eq!(inner.len(), 4, "table grew past its cap");
        assert!(inner.get(&9).is_some(), "new session missing");
        assert!(inner.get(&0).is_some(), "recent session evicted");
        assert!(inner.get(&1).is_none(), "LRU session kept");
    }

    /// Replay detection must survive pruning: a duplicate id is still rejected
    /// after the session is touched by a later packet.
    #[test]
    fn session_sweep_keeps_recent_packets_filtered() {
        let sessions = Udp2022Sessions::new();
        assert!(sessions.accept(1, 1));
        assert!(!sessions.accept(1, 1));
        // Another packet from a different session prunes the table.
        assert!(sessions.accept(2, 1));
        assert!(!sessions.accept(1, 1), "replay must stay rejected");
    }
}
