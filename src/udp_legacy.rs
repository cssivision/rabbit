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

use crate::cipher::Cipher;
use bytes::Bytes;

use crate::util::{generate_raw_addr, parse_address};

/// Seal one datagram: fresh seed, address prefix, payload and the tag space
/// that AEAD methods keep at the end.
///
/// Every datagram is self-contained, so each one gets its own seed: the cipher
/// is reset from `cipher` for that purpose.
pub fn seal(cipher: &Cipher, host: &str, port: u16, payload: &[u8]) -> io::Result<Bytes> {
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
    Ok(Bytes::from(data))
}

/// Open one datagram: read its seed, decrypt, drop the tag and parse the
/// address prefix that the sender put in front of the payload.
pub fn open(cipher: &mut Cipher, packet: &[u8]) -> io::Result<(String, u16, Bytes)> {
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
    Ok((host, port, Bytes::from(body)))
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
            assert_eq!(&body[..], payload);
        }
    }
}
