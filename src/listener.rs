use std::fs;
use std::io;

use awak::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use futures_util::{AsyncRead, AsyncWrite};

pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl AsyncReadWrite for TcpStream {}

impl AsyncReadWrite for UnixStream {}

impl Listener {
    pub async fn bind(addr: &str, unix_socket: bool) -> io::Result<Listener> {
        if unix_socket {
            let _ = fs::remove_file(&addr);
            Ok(Listener::Unix(UnixListener::bind(addr)?))
        } else {
            Ok(Listener::Tcp(TcpListener::bind(addr).await?))
        }
    }

    pub async fn accept(&self) -> io::Result<Box<dyn AsyncReadWrite + Unpin + Send>> {
        match self {
            Listener::Unix(lis) => {
                let (stream, addr) = lis.accept().await?;
                log::debug!("accept stream from addr {:?}", addr);
                Ok(Box::new(stream))
            }
            Listener::Tcp(lis) => {
                let (stream, addr) = lis.accept().await?;
                log::debug!("accept stream from addr {:?}", addr);
                Ok(Box::new(stream))
            }
        }
    }
}
