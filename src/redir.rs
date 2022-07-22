use std::future::pending;
use std::future::Future;
use std::io::{self, Error};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use awak::net::{TcpListener, TcpStream, UdpSocket};
use awak::time::timeout;
use futures_util::{future::join, AsyncRead, AsyncWrite, Stream};
use socket2::SockAddr;

use crate::cipher::Cipher;
use crate::config::{self, Mode};
use crate::io::{copy_bidirectional, write_all, IdleTimeout, DEFAULT_IDLE_TIMEOUT};
use crate::util::{generate_raw_addr, other};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_RESLOVE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UDP_BUFFER_SIZE: usize = 65536;

pub struct Server {
    services: Vec<Service>,
}

impl Server {
    pub fn new(configs: Vec<config::Redir>) -> Server {
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
        let local_addr = self.config.local_addr.clone();
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
                get_original_dst_addr(&socket)?
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
    sender: async_channel::Sender<(Vec<u8>, SocketAddr)>,
    original_dst_addr: SocketAddr,
) -> io::Result<(u64, u64)> {
    let cipher = Arc::new(Mutex::new(cipher));
    let rawaddr = generate_raw_addr(
        &original_dst_addr.ip().to_string(),
        original_dst_addr.port(),
    );
    write_all(cipher.clone(), &mut socket2, &rawaddr).await?;

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
    )
    .await??;
    log::debug!("proxy local => remote: {}, remote => local: {:?}", n1, n2);
    Ok((n1, n2))
}

fn get_original_dst_addr(s: &TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();

    unsafe {
        let (_, target_addr) = SockAddr::init(|target_addr, target_addr_len| {
            match s.local_addr()? {
                SocketAddr::V4(..) => {
                    let ret = libc::getsockopt(
                        fd,
                        libc::SOL_IP,
                        libc::SO_ORIGINAL_DST,
                        target_addr as *mut _,
                        target_addr_len, // libc::socklen_t
                    );
                    if ret != 0 {
                        let err = Error::last_os_error();
                        return Err(err);
                    }
                }
                SocketAddr::V6(..) => {
                    let ret = libc::getsockopt(
                        fd,
                        libc::SOL_IPV6,
                        libc::IP6T_SO_ORIGINAL_DST,
                        target_addr as *mut _,
                        target_addr_len, // libc::socklen_t
                    );

                    if ret != 0 {
                        let err = Error::last_os_error();
                        return Err(err);
                    }
                }
            }
            Ok(())
        })?;

        // Convert sockaddr_storage to SocketAddr
        Ok(target_addr.as_socket().expect("SocketAddr"))
    }
}
