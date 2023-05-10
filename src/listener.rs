use std::fs;
use std::io;
use std::net::SocketAddr;

use futures_util::{AsyncRead, AsyncWrite, Stream, StreamExt};
use slings::net::{TcpListener, TcpStream, UnixListener, UnixStream};

use crate::config::Addr;

pub enum Listener {
    Tcp(Box<dyn Stream<Item = io::Result<(TcpStream, SocketAddr)>> + Unpin>),
    Unix(UnixListener),
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}

impl AsyncReadWrite for TcpStream {}

impl AsyncReadWrite for UnixStream {}

impl Listener {
    pub async fn bind(addr: Addr) -> io::Result<Listener> {
        match addr {
            Addr::Path(addr) => {
                let _ = fs::remove_file(&addr);
                Ok(Listener::Unix(UnixListener::bind(addr)?))
            }
            Addr::Socket(addr) => Ok(Listener::Tcp(Box::new(
                TcpListener::bind(addr)?.accept_multi(),
            ))),
        }
    }

    pub async fn accept(&mut self) -> io::Result<Box<dyn AsyncReadWrite>> {
        match self {
            Listener::Unix(lis) => {
                let (stream, addr) = lis.accept().await?;
                log::debug!("accept stream from addr {:?}", addr);
                Ok(Box::new(stream))
            }
            Listener::Tcp(lis) => {
                if let Some(v) = lis.next().await {
                    let (stream, addr) = v?;
                    log::debug!("accept stream from addr {:?}", addr);
                    Ok(Box::new(stream))
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                }
            }
        }
    }
}
