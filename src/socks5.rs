use std::io;
use std::time::Duration;

use awak::time::timeout;
use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::util::read_address;

pub mod v5 {
    pub const VERSION: u8 = 5;
    pub const METH_NO_AUTH: u8 = 0;
    pub const CMD_CONNECT: u8 = 1;
    pub const TYPE_IPV4: u8 = 1;
    pub const TYPE_IPV6: u8 = 4;
    pub const TYPE_DOMAIN: u8 = 3;
    pub const REPLY_SUCESS: u8 = 0;
}

/// Creates a future which will handle socks5 connection.
///
/// if success The returned future will the handled `TcpStream` and address. if handle shake fail will
/// return `io::Error`.
pub async fn handshake<A>(conn: &mut A, dur: Duration) -> io::Result<(String, u16)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let fut = async move {
        // socks version, only support version 5.
        let buf1 = &mut [0u8; 2];
        conn.read_exact(buf1).await?;

        if buf1[0] != v5::VERSION {
            return Err(io::Error::other("unknown version"));
        }

        let buf2 = &mut vec![0u8; buf1[1] as usize];
        conn.read_exact(buf2).await?;

        let buf3 = &mut [v5::VERSION, v5::METH_NO_AUTH];
        conn.write_all(buf3).await?;

        // check version
        let buf4 = &mut [0u8; 3];
        conn.read_exact(buf4).await?;
        if buf4[0] != v5::VERSION {
            return Err(io::Error::other("didn't confirm with v5 version"));
        }
        // checkout cmd
        if buf4[1] != v5::CMD_CONNECT {
            return Err(io::Error::other("unsupported command"));
        }
        // there's one byte which is reserved for future use, so we read it and discard it.

        let (raw, host, port) = read_address(conn).await?;

        // Sending connection established message immediately to client.
        // This some round trip time for creating socks connection with the client.
        // But if connection failed, the client will get connection reset error.
        let mut resp = vec![v5::VERSION, v5::REPLY_SUCESS, 0x00];
        resp.extend_from_slice(&raw);
        conn.write_all(&resp).await?;

        Ok((host, port))
    };
    timeout(dur, fut).await?
}
