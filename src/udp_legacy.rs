//! Datagram framing of the pre-SIP022 ("legacy") UDP protocol.
//!
//! A datagram is `seed | address | payload` where AEAD methods keep the
//! authentication tag at the very end of the encrypted part:
//!
//! ```text
//! stream cipher:  IV  | ATYP + address + port | payload
//! AEAD cipher:    salt | ATYP + address + port | payload | tag
//! ```
//!
//! Both sides of the relay use these helpers, so the layout is defined once.

use std::io;
use std::net::Ipv4Addr;

use crate::cipher::Cipher;
use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};
use crate::util::generate_raw_addr;

/// Parse a SOCKS5 address prefix, returning how many bytes it occupies.
pub fn parse_address(buf: &[u8]) -> io::Result<(usize, String, u16)> {
    let atyp = match buf.first() {
        Some(atyp) => *atyp,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty address",
            ))
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

/// Seal one datagram: fresh seed, address prefix, payload and the tag space
/// that AEAD methods keep at the end.
pub fn seal(cipher: &Cipher, host: &str, port: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    // A datagram is self-contained, so every one carries its own seed.
    let mut cipher = cipher.reset();
    cipher.init_encrypt();

    let seed_len = cipher.seed_len();
    let mut data = cipher.encrypt_seed().as_bytes().to_vec();
    data.extend_from_slice(&generate_raw_addr(host, port));
    data.extend_from_slice(payload);
    if cipher.is_aead() {
        data.extend_from_slice(&vec![0u8; cipher.tag_size()]);
    }
    cipher.encrypt_in_place(&mut data[seed_len..])?;
    Ok(data)
}

/// Open one datagram: read its seed, decrypt, drop the tag and parse the
/// address prefix that the sender put in front of the payload.
pub fn open(cipher: &mut Cipher, packet: &[u8]) -> io::Result<(String, u16, Vec<u8>)> {
    let seed_len = cipher.seed_len();
    if packet.len() < seed_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "datagram shorter than its seed",
        ));
    }
    cipher
        .decrypt_seed_mut()
        .as_mut_bytes()
        .copy_from_slice(&packet[..seed_len]);
    cipher.init_decrypt();

    let mut body = packet[seed_len..].to_vec();
    cipher.decrypt_in_place(&mut body)?;
    if cipher.is_aead() {
        let tag = cipher.tag_size();
        if body.len() < tag {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated tag",
            ));
        }
        body.truncate(body.len() - tag);
    }

    let (n, host, port) = parse_address(&body)?;
    body.drain(..n);
    Ok((host, port, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Method;

    #[test]
    fn round_trip_aead_and_stream() {
        for method in [Method::Aes128Gcm, Method::Aes256Cfb, Method::ChaCha20Ietf] {
            let cipher = Cipher::new(method, "password").unwrap();
            let sealer = cipher.reset();
            let mut opener = cipher.reset();
            let payload = b"hello legacy udp";
            let datagram = seal(&sealer, "127.0.0.1", 8080, payload).unwrap();
            let (host, port, body) = open(&mut opener, &datagram).unwrap();
            assert_eq!(host, "127.0.0.1");
            assert_eq!(port, 8080);
            assert_eq!(body, payload);
        }
    }
}
