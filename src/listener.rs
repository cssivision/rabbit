use std::fs;
use std::io;

use futures_util::{AsyncRead, AsyncWrite};
use slings::net::{TcpListener, TcpStream, UnixListener, UnixStream};

use crate::config::Addr;

pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}

impl AsyncReadWrite for TcpStream {}

impl AsyncReadWrite for UnixStream {}

impl Listener {
    pub fn bind(addr: Addr) -> io::Result<Listener> {
        match addr {
            Addr::Path(addr) => {
                let _ = fs::remove_file(&addr);
                Ok(Listener::Unix(UnixListener::bind(addr)?))
            }
            Addr::Socket(addr) => Ok(Listener::Tcp(TcpListener::bind(addr)?)),
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
                let (stream, addr) = lis.accept2().await?;
                log::debug!("accept stream from addr {:?}", addr);
                Ok(Box::new(stream))
            }
        }
    }
}
