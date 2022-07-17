use std::future::pending;
use std::io::{self, Error};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use awak::net::{TcpListener, TcpStream};
use awak::time::timeout;
use futures_util::{AsyncRead, AsyncWrite};
use socket2::SockAddr;

use crate::cipher::Cipher;
use crate::config;
use crate::io::{copy_bidirectional, write_all, IdleTimeout, DEFAULT_IDLE_TIMEOUT};
use crate::util::generate_raw_addr;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

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
        let cipher = Cipher::new(&self.config.method, &self.config.password);
        let local_addr = self.config.local_addr.clone();
        let listener = TcpListener::bind(local_addr).await?;
        log::info!("listening connections on {:?}", self.config.local_addr);
        loop {
            let (mut socket, addr) = listener.accept().await?;
            log::debug!("accept stream from addr {:?}", addr);
            let cipher = cipher.reset();
            let server_addr = self.config.server_addr;
            let original_dst_addr = get_original_dst_addr(&socket)?;
            let proxy = async move {
                if let Err(e) = proxy(server_addr, cipher, &mut socket, original_dst_addr).await {
                    log::error!("failed to proxy; error={}", e);
                }
            };
            awak::spawn(proxy).detach();
        }
    }
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
