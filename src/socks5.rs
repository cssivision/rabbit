#![allow(clippy::many_single_char_names)]
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

use crate::util::other;

use awak::io::{AsyncReadExt, AsyncWriteExt};
use awak::net::TcpStream;

pub mod v5 {
    pub const VERSION: u8 = 5;
    pub const METH_NO_AUTH: u8 = 0;
    pub const CMD_CONNECT: u8 = 1;
    pub const TYPE_IPV4: u8 = 1;
    pub const TYPE_IPV6: u8 = 4;
    pub const TYPE_DOMAIN: u8 = 3;
}

/// Creates a future which will handle socks5 connection.
///
/// if success The returned future will the handled `TcpStream` and address. if handle shake fail will
/// return `io::Error`.
pub async fn serve(conn: &mut TcpStream) -> io::Result<(String, u16)> {
    // socks version, only support version 5.
    let buf1 = &mut [0u8; 2];
    conn.read_exact(buf1).await?;

    if buf1[0] != v5::VERSION {
        return Err(other("unknown version"));
    }

    let buf2 = &mut vec![0u8; buf1[1] as usize];
    conn.read_exact(buf2).await?;

    let buf3 = &mut [v5::VERSION, v5::METH_NO_AUTH];
    conn.write_all(buf3).await?;

    // check version
    let buf4 = &mut [0u8; 3];
    conn.read_exact(buf4).await?;
    if buf4[0] != v5::VERSION {
        return Err(other("didn't confirm with v5 version"));
    }
    // checkout cmd
    if buf4[1] != v5::CMD_CONNECT {
        return Err(other("unsupported command"));
    }
    // there's one byte which is reserved for future use, so we read it and discard it.

    let address_type = &mut [0u8];
    conn.read_exact(address_type).await?;

    let result = match address_type.get(0) {
        // For IPv4 addresses, we read the 4 bytes for the address as
        // well as 2 bytes for the port.
        Some(&v5::TYPE_IPV4) => {
            let buf = &mut [0u8; 6];
            conn.read_exact(buf).await?;
            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);

            let mut resp = vec![v5::VERSION, 0x00, 0x00, v5::TYPE_IPV4];
            resp.extend_from_slice(buf);
            conn.write_all(&resp).await?;

            Ok((format!("{}", addr), port))
        }

        // For IPv6 addresses there's 16 bytes of an address plus two
        // bytes for a port, so we read that off and then keep going.
        Some(&v5::TYPE_IPV6) => {
            let buf = &mut [0u8; 18];
            conn.read_exact(buf).await?;
            let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
            let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
            let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
            let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
            let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
            let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
            let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
            let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
            let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
            let port = ((buf[16] as u16) << 8) | (buf[17] as u16);

            let mut resp = vec![v5::VERSION, 0x00, 0x00, v5::TYPE_IPV6];
            resp.extend_from_slice(buf);
            conn.write_all(&resp).await?;

            Ok((format!("{}", addr), port))
        }

        // The SOCKSv5 protocol not only supports proxying to specific
        // IP addresses, but also arbitrary hostnames.
        Some(&v5::TYPE_DOMAIN) => {
            let buf1 = &mut [0u8];
            conn.read_exact(buf1).await?;
            let buf2 = &mut vec![0u8; buf1[0] as usize + 2];
            conn.read_exact(buf2).await?;

            let hostname = &buf2[..buf2.len() - 2];
            let hostname = if let Ok(hostname) = str::from_utf8(hostname) {
                hostname
            } else {
                return Err(other("hostname include invalid utf8"));
            };

            let pos = buf2.len() - 2;
            let port = ((buf2[pos] as u16) << 8) | (buf2[pos + 1] as u16);

            let mut resp = vec![v5::VERSION, 0x00, 0x00, v5::TYPE_DOMAIN];
            resp.extend_from_slice(buf1);
            resp.extend_from_slice(buf2);
            conn.write_all(&resp).await?;

            Ok((hostname.to_string(), port))
        }
        n => {
            let msg = format!("unknown address type, received: {:?}", n);
            Err(other(&msg))
        }
    };

    // Sending connection established message immediately to client.
    // This some round trip time for creating socks connection with the client.
    // But if connection failed, the client will get connection reset error.
    // let resp = &[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43];
    // conn.write_all(resp).await?;

    result
}
