use std::fs;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use awak::net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream};
use futures_util::{AsyncRead, AsyncWrite};
use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Addr;

fn bind_socket(addr: SocketAddr, ty: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), ty, Some(protocol))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(
        unix,
        not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
    ))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

pub fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = bind_socket(addr, Type::STREAM, Protocol::TCP)?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

pub fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = bind_socket(addr, Type::DGRAM, Protocol::UDP)?;
    UdpSocket::from_std(socket.into())
}

pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Stream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_close(cx),
            Stream::Unix(s) => Pin::new(s).poll_close(cx),
        }
    }
}

impl Listener {
    pub async fn bind(addr: Addr) -> io::Result<Listener> {
        match addr {
            Addr::Path(addr) => {
                let _ = fs::remove_file(&addr);
                Ok(Listener::Unix(UnixListener::bind(addr)?))
            }
            Addr::Socket(addr) => Ok(Listener::Tcp(bind_tcp(addr)?)),
        }
    }

    pub async fn accept(&self) -> io::Result<Stream> {
        match self {
            Listener::Unix(lis) => {
                let (stream, addr) = lis.accept().await?;
                log::debug!("accept stream from addr {:?}", addr);
                Ok(Stream::Unix(stream))
            }
            Listener::Tcp(lis) => {
                let (stream, addr) = lis.accept().await?;
                log::debug!("accept stream from addr {:?}", addr);
                Ok(Stream::Tcp(stream))
            }
        }
    }
}
