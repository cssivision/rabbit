use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use awak::net::{TcpListener, TcpStream, UdpSocket};
use awak::time::timeout;
use awak::util::IdleTimeout;
use futures_channel::mpsc::{channel, Receiver, Sender};
use futures_util::{future::join, AsyncRead, AsyncWrite, Stream};
use socket2::SockAddr;

use crate::cipher::Cipher;
use crate::config::{self, Mode};
use crate::io::{copy_bidirectional, write_all, DEFAULT_CHECK_INTERVAL, DEFAULT_IDLE_TIMEOUT};
use crate::util::{generate_raw_addr, other};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UDP_BUFFER_SIZE: usize = 65536;

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

    pub async fn stream_relay(&self) -> io::Result<()> {
        let cipher = Cipher::new(&self.config.method, &self.config.password);
        let local_addr = self.config.local_addr;
        let listener = TcpListener::bind(local_addr).await?;
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
        let cipher = Cipher::new(&self.config.method, &self.config.password);
        let socket = UdpSocket::bind(self.config.local_addr)?;
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
        Ok(addr.as_socket().expect("SocketAddr"))
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
                    awak::spawn(async move {
                        if let Err(e) =
                            proxy_packet(server_addr, cipher, buf, peer_addr, redir_addr, sender)
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
) -> io::Result<(u64, u64)> {
    let redir_addr = if let Some(redir_addr) = redir_addr {
        redir_addr
    } else {
        unimplemented!()
    };
    cipher.init_encrypt();
    let mut data = cipher.iv().to_vec();
    let rawaddr = generate_raw_addr(&redir_addr.ip().to_string(), redir_addr.port());
    data.extend_from_slice(&rawaddr);
    data.extend_from_slice(&buf);
    cipher.encrypt(&mut data[cipher.iv_len()..]);

    let local: SocketAddr = ([0u8; 4], 0).into();
    // send to and recv from target.
    let socket = UdpSocket::bind(local)?;
    socket.connect(server_addr)?;
    let _ = socket.send(&data).await?;
    let mut recv_buf = vec![0u8; MAX_UDP_BUFFER_SIZE];
    let n = socket.recv(&mut recv_buf).await?;
    recv_buf.truncate(n);

    cipher.init_decrypt();
    cipher.decrypt(&mut recv_buf);
    sender
        .try_send((recv_buf.to_vec(), peer_addr))
        .map_err(|e| other(&format!("send fail: {e}")))?;
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
    let cipher = Arc::new(Mutex::new(cipher));

    let mut socket2 = timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect(&server_addr)).await??;
    log::debug!("connected to server {}", server_addr);

    let rawaddr = generate_raw_addr(
        &original_dst_addr.ip().to_string(),
        original_dst_addr.port(),
    );
    write_all(cipher.clone(), &mut socket2, &rawaddr).await?;

    let (n1, n2) = IdleTimeout::new(
        copy_bidirectional(socket1, &mut socket2, cipher),
        DEFAULT_IDLE_TIMEOUT,
        DEFAULT_CHECK_INTERVAL,
    )
    .await??;
    log::debug!("proxy local => remote: {}, remote => local: {:?}", n1, n2);
    Ok((n1, n2))
}
