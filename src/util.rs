use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use futures_util::{AsyncRead, AsyncReadExt};
use hkdf::Hkdf;
use md5::compute;
use sha1::Sha1;

use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};

const MD5_LENGTH: u32 = 16;
const AEAD2022_SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// Buffer size for the relay copy between the two halves of a proxied
/// connection.
///
/// `awak`'s default is 2 KiB, so every relay record is 2 KiB: each one costs an
/// AEAD call, a length header and an allocation. Copying 64 KiB at a time lets
/// the cipher emit a few full-size records per syscall instead.
pub const COPY_BUFFER_SIZE: usize = 64 * 1024;

pub fn derive_blake3_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut key_material = key.to_vec();
    key_material.extend_from_slice(salt);
    blake3::derive_key(AEAD2022_SESSION_SUBKEY_CONTEXT, &key_material).to_vec()
}

pub fn hkdf_sha1(secret: &[u8], salt: &[u8], info: &[u8], outkey: &mut [u8]) -> io::Result<()> {
    let hk = Hkdf::<Sha1>::new(Some(salt), secret);
    hk.expand(info, outkey)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(())
}

pub fn generate_key(data: &[u8], key_len: usize) -> Vec<u8> {
    let count = (key_len as f32 / MD5_LENGTH as f32).ceil() as u32;
    let mut key = Vec::from(&compute(data)[..]);
    let mut start = 0;
    for _ in 1..count {
        start += MD5_LENGTH;
        let mut d = Vec::from(&key[(start - MD5_LENGTH) as usize..start as usize]);
        d.extend_from_slice(data);
        let d = compute(d);
        key.extend_from_slice(&*d);
    }
    key.truncate(key_len);
    key
}

pub fn generate_raw_addr(host: &str, port: u16) -> Vec<u8> {
    match IpAddr::from_str(host) {
        Ok(IpAddr::V4(host)) => {
            let mut rawaddr = vec![TYPE_IPV4];
            rawaddr.extend_from_slice(&host.octets());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
        Ok(IpAddr::V6(host)) => {
            let mut rawaddr = vec![TYPE_IPV6];
            rawaddr.extend_from_slice(&host.octets());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
        _ => {
            let dm_len = host.len();
            let mut rawaddr = vec![TYPE_DOMAIN, dm_len as u8];
            rawaddr.extend_from_slice(host.as_bytes());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
    }
}

/// Generate a random SIP022 session id.
///
/// Zero is not a valid session id, so it is remapped to 1. Collisions are
/// harmless: the peer distinguishes sessions by id, and a repeat only matters if
/// it happens within `DEFAULT_UDP2022_SESSION_TIMEOUT`.
pub fn random_session_id() -> u64 {
    let mut buf = [0u8; 8];
    rand::fill(&mut buf[..]);
    let id = u64::from_be_bytes(buf);
    if id == 0 { 1 } else { id }
}

/// Parse a SOCKS5 address prefix, returning how many bytes it occupies.
pub fn parse_address(buf: &[u8]) -> io::Result<(usize, String, u16)> {
    let atyp = match buf.first() {
        Some(atyp) => *atyp,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty address",
            ));
        }
    };
    match atyp {
        TYPE_IPV4 => {
            if buf.len() < 7 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short ipv4"));
            }
            let addr = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((7, format!("{addr}"), port))
        }
        TYPE_IPV6 => {
            if buf.len() < 19 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short ipv6"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let addr = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((19, format!("{addr}"), port))
        }
        TYPE_DOMAIN => {
            let len = match buf.get(1) {
                Some(len) => *len as usize,
                None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short domain")),
            };
            let end = 2 + len + 2;
            if buf.len() < end {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short domain"));
            }
            let host = String::from_utf8_lossy(&buf[2..2 + len]).into_owned();
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Ok((end, host, port))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported address type {other}"),
        )),
    }
}

/// Read a SOCKS5 address (`[atyp][addr][port]`) from `conn`.
///
/// Returns the bytes exactly as they arrived next to the decoded host and port:
/// a SOCKS5 reply has to echo the address back, and re-encoding it would turn an
/// address that arrived as a hostname into a different one.
pub async fn read_address<A>(conn: &mut A) -> io::Result<(Vec<u8>, String, u16)>
where
    A: AsyncRead + Unpin + ?Sized,
{
    let mut buf = vec![0u8; 1];
    conn.read_exact(&mut buf).await?;

    // Total address length, type byte included: the fixed-size forms are known
    // from the type byte alone, while a domain announces its own length in the
    // byte that follows it.
    let total = match buf[0] {
        TYPE_IPV4 => 1 + 6,
        TYPE_IPV6 => 1 + 18,
        TYPE_DOMAIN => {
            let len = &mut [0u8; 1];
            conn.read_exact(len).await?;
            buf.push(len[0]);
            2 + len[0] as usize + 2
        }
        n => {
            let msg = format!("unknown address type, received: {n:?}");
            return Err(io::Error::other(msg));
        }
    };

    let filled = buf.len();
    buf.resize(total, 0);
    conn.read_exact(&mut buf[filled..]).await?;

    let (consumed, host, port) = parse_address(&buf)?;
    buf.truncate(consumed);

    // `parse_address` decodes a domain lossily so the UDP codecs can pass
    // through whatever bytes an older peer sent, but a SOCKS5 client must send
    // valid UTF-8. Reject it here rather than resolving a mangled name.
    if buf[0] == TYPE_DOMAIN && std::str::from_utf8(&buf[2..buf.len() - 2]).is_err() {
        return Err(io::Error::other("hostname include invalid utf8"));
    }

    Ok((buf, host, port))
}
