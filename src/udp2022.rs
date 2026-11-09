//! AEAD-2022 (SIP022) UDP packet handling.
//!
//! Unlike the legacy AEAD methods, the 2022 methods do not prefix every
//! datagram with a salt. Instead the packet starts with an encrypted
//! "separate header" that carries the session id and a packet counter, and the
//! body is sealed with a session subkey derived from the session id:
//!
//! * `2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm`
//!   `[16B AES-ECB(psk, session_id | packet_id)] [AES-GCM body] [16B tag]`
//!   nonce = plaintext `session_id | packet_id` bytes `4..16`; the body starts
//!   at the socket type byte, so the encrypted header is not part of the tag.
//! * `2022-blake3-chacha20-poly1305`
//!   `[24B nonce] [XChaCha20-Poly1305 body] [16B tag]`, sealed with the psk,
//!   and the body starts with the session id / packet id.
//!
//! See https://shadowsocks.org/doc/sip022.html.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use bytes::{Buf, Bytes};

use crate::cipher::{Cipher, Method, udp_open, udp_seal};
use crate::util::{derive_blake3_subkey, generate_raw_addr, parse_address};

/// Client -> server packet.
const CLIENT_TYPE: u8 = 0;
/// Server -> client packet.
const SERVER_TYPE: u8 = 1;
/// Maximum allowed clock skew of the timestamp field, in seconds.
const TIMESTAMP_MAX_DIFF: u64 = 30;

/// AES-GCM methods carry a 16 byte encrypted separate header.
const AES_HEADER_LEN: usize = 16;
/// ChaCha20-Poly1305 methods carry a 24 byte nonce.
const CHACHA_NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// A decrypted client -> server packet.
pub struct ClientPacket {
    pub client_session_id: u64,
    pub packet_id: u64,
    pub host: String,
    pub port: u16,
    pub payload: Bytes,
}

/// A decrypted server -> client packet.
pub struct ServerPacket {
    pub server_session_id: u64,
    pub packet_id: u64,
    pub client_session_id: u64,
    pub host: String,
    pub port: u16,
    pub payload: Bytes,
}

/// 2022 UDP cipher state: the pre-shared key plus the method.
pub struct Udp2022 {
    method: Method,
    psk: Vec<u8>,
    /// Most recently derived session subkey.
    ///
    /// The subkey depends only on `(psk, session_id)`, so it is constant for the
    /// lifetime of a session. A relay sees long runs of packets from the same
    /// session, so caching the last one turns a BLAKE3 XOF per packet into one
    /// per session. ChaCha20 methods do not use it: they seal with the psk.
    ///
    /// A plain field, not a lock: a `Udp2022` is owned by one task and only ever
    /// used through `&mut self` (see `subkey`), so there is nothing to
    /// synchronise.
    cached_subkey: Option<(u64, Vec<u8>)>,
}

impl Udp2022 {
    pub fn new(method: Method, psk: &[u8]) -> io::Result<Udp2022> {
        if !crate::cipher::is_aead2022(&method) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an AEAD 2022 method",
            ));
        }
        if psk.len() != method.psk_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "key length must be {} for 2022 AEAD ciphers",
                    method.psk_len()
                ),
            ));
        }
        Ok(Udp2022 {
            method,
            psk: psk.to_vec(),
            cached_subkey: None,
        })
    }

    /// The SIP022 codec for `cipher`, or `None` when the method is not a 2022
    /// one.
    ///
    /// Both the listener and every flow need this, and keeping the "only build
    /// it for 2022 methods" decision in one place stops the two from drifting.
    pub fn from_cipher(cipher: &Cipher) -> io::Result<Option<Udp2022>> {
        if cipher.is_aead2022() {
            Ok(Some(Udp2022::new(cipher.method(), cipher.key())?))
        } else {
            Ok(None)
        }
    }

    /// Session subkey: `blake3::derive_key(psk || session_id_be)`.
    ///
    /// Cached: see the field docs. Takes `&mut self` so the cache needs no lock.
    fn subkey(&mut self, session_id: u64) -> Vec<u8> {
        if let Some((id, key)) = self.cached_subkey.as_ref()
            && *id == session_id
        {
            // The caller needs the bytes past this borrow, so this one clone
            // stays; `packet_key` avoids it by borrowing instead.
            return key.clone();
        }

        let mut key = derive_blake3_subkey(&self.psk, &session_id.to_be_bytes());
        key.truncate(self.method.psk_len());
        self.cached_subkey = Some((session_id, key.clone()));
        key
    }

    /// Key that seals one packet.
    ///
    /// The ChaCha20 method seals with the pre-shared key itself and carries a
    /// random 192 bit nonce in front of the packet; the AES methods derive a
    /// subkey per session id and reuse the 96 bit nonce from the encrypted
    /// header.
    ///
    /// Borrows the key, so a cached subkey costs no copy.
    fn packet_key(&mut self, session_id: u64) -> &[u8] {
        if self.method.is_chacha2022() {
            &self.psk
        } else {
            if self.cached_subkey.as_ref().map(|(id, _)| *id) != Some(session_id) {
                self.subkey(session_id);
            }
            &self.cached_subkey.as_ref().expect("just populated").1
        }
    }

    /// Seal `plaintext` in place, appending the 16 byte authentication tag.
    fn seal(&mut self, session_id: u64, nonce: &[u8], plaintext: Vec<u8>) -> io::Result<Vec<u8>> {
        let mut buffer = plaintext;
        udp_seal(self.method, self.packet_key(session_id), nonce, &mut buffer)?;
        Ok(buffer)
    }

    /// Open a sealed body, stripping the authentication tag.
    fn open(&mut self, session_id: u64, nonce: &[u8], ciphertext: Vec<u8>) -> io::Result<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "packet shorter than the AEAD tag",
            ));
        }
        let mut buffer = ciphertext;
        udp_open(self.method, self.packet_key(session_id), nonce, &mut buffer)?;
        Ok(buffer)
    }

    /// Decrypt a client -> server datagram.
    pub fn decrypt_client_packet(&mut self, packet: &[u8]) -> io::Result<ClientPacket> {
        // `plaintext` holds the decrypted body and is consumed as the cursor:
        // whatever remains after the header is the payload, without a copy.
        let (session_id, packet_id, mut plaintext) = self.open_packet(packet)?;
        if self.method.is_chacha2022() {
            let body_session_id = plaintext.try_get_u64()?;
            let body_packet_id = plaintext.try_get_u64()?;
            if body_session_id != session_id || body_packet_id != packet_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session id or packet id mismatch in packet header",
                ));
            }
        }
        let socket_type = plaintext.try_get_u8()?;
        if socket_type != CLIENT_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid socket type {socket_type:#x}, expecting {CLIENT_TYPE:#x}"),
            ));
        }
        check_timestamp(plaintext.try_get_u64()?)?;
        skip_padding(&mut plaintext)?;
        let (consumed, host, port) = parse_address(&plaintext)?;
        plaintext.advance(consumed);

        Ok(ClientPacket {
            client_session_id: session_id,
            packet_id,
            host,
            port,
            payload: plaintext,
        })
    }

    /// Decrypt a server -> client datagram.
    pub fn decrypt_server_packet(&mut self, packet: &[u8]) -> io::Result<ServerPacket> {
        let (session_id, packet_id, mut plaintext) = self.open_packet(packet)?;
        if self.method.is_chacha2022() {
            let body_session_id = plaintext.try_get_u64()?;
            let body_packet_id = plaintext.try_get_u64()?;
            if body_session_id != session_id || body_packet_id != packet_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session id or packet id mismatch in packet header",
                ));
            }
        }
        let socket_type = plaintext.try_get_u8()?;
        if socket_type != SERVER_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid socket type {socket_type:#x}, expecting {SERVER_TYPE:#x}"),
            ));
        }
        check_timestamp(plaintext.try_get_u64()?)?;
        let client_session_id = plaintext.try_get_u64()?;
        skip_padding(&mut plaintext)?;
        let (consumed, host, port) = parse_address(&plaintext)?;
        plaintext.advance(consumed);

        Ok(ServerPacket {
            server_session_id: session_id,
            packet_id,
            client_session_id,
            host,
            port,
            payload: plaintext,
        })
    }

    /// Build a client -> server datagram.
    pub fn encrypt_client_packet(
        &mut self,
        client_session_id: u64,
        packet_id: u64,
        host: &str,
        port: u16,
        payload: &[u8],
    ) -> io::Result<Bytes> {
        let mut body = Vec::with_capacity(64 + payload.len());
        if self.method.is_chacha2022() {
            body.extend_from_slice(&client_session_id.to_be_bytes());
            body.extend_from_slice(&packet_id.to_be_bytes());
        }
        body.push(CLIENT_TYPE);
        body.extend_from_slice(&now().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&generate_raw_addr(host, port));
        body.extend_from_slice(payload);
        self.seal_packet(client_session_id, packet_id, body)
    }

    /// Build a server -> client datagram.
    ///
    /// `source` is the address the reply came from, which is what the peer sees
    /// in the header.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_server_packet(
        &mut self,
        server_session_id: u64,
        packet_id: u64,
        client_session_id: u64,
        host: &str,
        port: u16,
        payload: &[u8],
    ) -> io::Result<Bytes> {
        let mut body = Vec::with_capacity(64 + payload.len());
        if self.method.is_chacha2022() {
            body.extend_from_slice(&server_session_id.to_be_bytes());
            body.extend_from_slice(&packet_id.to_be_bytes());
        }
        body.push(SERVER_TYPE);
        body.extend_from_slice(&now().to_be_bytes());
        body.extend_from_slice(&client_session_id.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&generate_raw_addr(host, port));
        body.extend_from_slice(payload);
        self.seal_packet(server_session_id, packet_id, body)
    }

    /// Encrypt a body and prepend the separate header (AES-ECB) or the nonce
    /// (ChaCha20-Poly1305).
    fn seal_packet(&mut self, session_id: u64, packet_id: u64, body: Vec<u8>) -> io::Result<Bytes> {
        if self.method.is_chacha2022() {
            let mut nonce = vec![0u8; CHACHA_NONCE_LEN];
            rand::fill(&mut nonce[..]);
            let body = self.seal(session_id, &nonce, body)?;
            let mut packet = nonce;
            packet.extend_from_slice(&body);
            return Ok(Bytes::from(packet));
        }

        let mut header = Block::default();
        header[..8].copy_from_slice(&session_id.to_be_bytes());
        header[8..].copy_from_slice(&packet_id.to_be_bytes());
        let nonce = header[4..16].to_vec();
        self.encrypt_header(&mut header)?;
        let body = self.seal(session_id, &nonce, body)?;

        let mut packet = header.to_vec();
        packet.extend_from_slice(&body);
        Ok(Bytes::from(packet))
    }

    fn encrypt_header(&self, header: &mut Block) -> io::Result<()> {
        // The 16 byte separate header is AES-ECB encrypted with the psk, so the
        // key size decides which AES variant to use.
        match self.method {
            Method::Blake3Aes128Gcm => {
                let cipher = Aes128::new_from_slice(&self.psk).map_err(io::Error::other)?;
                cipher.encrypt_block(header);
            }
            _ => {
                let cipher = Aes256::new_from_slice(&self.psk).map_err(io::Error::other)?;
                cipher.encrypt_block(header);
            }
        }
        Ok(())
    }

    fn decrypt_header(&self, header: &mut Block) -> io::Result<()> {
        match self.method {
            Method::Blake3Aes128Gcm => {
                let cipher = Aes128::new_from_slice(&self.psk).map_err(io::Error::other)?;
                cipher.decrypt_block(header);
            }
            _ => {
                let cipher = Aes256::new_from_slice(&self.psk).map_err(io::Error::other)?;
                cipher.decrypt_block(header);
            }
        }
        Ok(())
    }

    /// Decrypt the envelope and return `(session_id, packet_id, plaintext_body)`.
    ///
    /// The body is a `Bytes` so the caller can slice the payload out of it
    /// without copying.
    fn open_packet(&mut self, packet: &[u8]) -> io::Result<(u64, u64, Bytes)> {
        if self.method.is_chacha2022() {
            if packet.len() < CHACHA_NONCE_LEN + 16 + TAG_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "packet too short",
                ));
            }
            let nonce = packet[..CHACHA_NONCE_LEN].to_vec();
            let body = self.open(0, &nonce, packet[CHACHA_NONCE_LEN..].to_vec())?;
            if body.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "packet too short",
                ));
            }
            let mut sid = [0u8; 8];
            sid.copy_from_slice(&body[..8]);
            let mut pid = [0u8; 8];
            pid.copy_from_slice(&body[8..16]);
            let session_id = u64::from_be_bytes(sid);
            let packet_id = u64::from_be_bytes(pid);
            return Ok((session_id, packet_id, Bytes::from(body)));
        }

        if packet.len() < AES_HEADER_LEN + 16 + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "packet too short",
            ));
        }
        let mut header = Block::default();
        header.copy_from_slice(&packet[..AES_HEADER_LEN]);
        self.decrypt_header(&mut header)?;
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&header[..8]);
        let mut pid = [0u8; 8];
        pid.copy_from_slice(&header[8..]);
        let nonce = header[4..16].to_vec();

        let session_id = u64::from_be_bytes(sid);
        let body = self.open(session_id, &nonce, packet[AES_HEADER_LEN..].to_vec())?;
        Ok((session_id, u64::from_be_bytes(pid), Bytes::from(body)))
    }
}

/// Sliding replay window over 64-bit packet ids, same shape as the WireGuard
/// counter window.
pub struct PacketWindow {
    last: u64,
    ring: [u64; RING_BLOCKS as usize],
}

const BLOCK_BIT_LOG: u32 = 6;
const RING_BLOCKS: u64 = 128;
const WINDOW_SIZE: u64 = (RING_BLOCKS - 1) * (1 << BLOCK_BIT_LOG);
const BLOCK_MASK: u64 = RING_BLOCKS - 1;
const BIT_MASK: u64 = (1 << BLOCK_BIT_LOG) - 1;

impl Default for PacketWindow {
    fn default() -> Self {
        PacketWindow {
            last: 0,
            ring: [0u64; RING_BLOCKS as usize],
        }
    }
}

impl PacketWindow {
    pub fn new() -> PacketWindow {
        PacketWindow::default()
    }

    /// Returns `true` if the packet id has not been seen yet (or is newer than
    /// the window), `false` if it is a duplicate or too old.
    pub fn validate(&mut self, packet_id: u64) -> bool {
        if packet_id == u64::MAX {
            return false;
        }

        let mut index_block = packet_id >> BLOCK_BIT_LOG;
        if packet_id > self.last {
            let current = self.last >> BLOCK_BIT_LOG;
            let mut diff = index_block - current;
            if diff > RING_BLOCKS {
                diff = RING_BLOCKS;
            }
            for d in 1..=diff {
                self.ring[((current + d) & BLOCK_MASK) as usize] = 0;
            }
            self.last = packet_id;
        } else if self.last - packet_id > WINDOW_SIZE {
            return false;
        }

        index_block &= BLOCK_MASK;
        let index_bit = packet_id & BIT_MASK;
        let old = self.ring[index_block as usize];
        let new = old | (1 << index_bit);
        self.ring[index_block as usize] = new;
        old != new
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reject a timestamp that is too far from now.
fn check_timestamp(ts: u64) -> io::Result<()> {
    let diff = now().abs_diff(ts);
    if diff > TIMESTAMP_MAX_DIFF {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid timestamp, clock skew {diff}s"),
        ));
    }
    Ok(())
}

/// Skip the padding field: `[u16 length][length bytes]`.
fn skip_padding(cursor: &mut Bytes) -> io::Result<()> {
    let n = cursor.try_get_u16()? as usize;
    if cursor.remaining() < n {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "packet too short",
        ));
    }
    cursor.advance(n);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK16: [u8; 16] = [0x11; 16];
    const PSK32: [u8; 32] = [0x22; 32];

    /// The cached subkey must match the one derived from scratch, and must be
    /// reused across packets of the same session.
    #[test]
    fn subkey_cache_returns_the_same_bytes() {
        let mut udp = Udp2022::new(Method::Blake3Aes128Gcm, &PSK16).unwrap();

        let first = udp.subkey(0x0102_0304_0506_0708);
        let expected = {
            let mut key = derive_blake3_subkey(&PSK16, &0x0102_0304_0506_0708u64.to_be_bytes());
            key.truncate(16);
            key
        };
        assert_eq!(first, expected, "first derivation differs");

        // Second call hits the cache; the value must be identical.
        assert_eq!(udp.subkey(0x0102_0304_0506_0708), first);
    }

    /// Switching session ids re-derives, and switching back must still be
    /// correct (the cache is single-slot, so the old entry is replaced).
    #[test]
    fn subkey_cache_handles_session_switches() {
        let mut udp = Udp2022::new(Method::Blake3Aes256Gcm, &PSK32).unwrap();

        let a = udp.subkey(1);
        let b = udp.subkey(2);
        assert_ne!(a, b, "different sessions must derive different subkeys");
        assert_eq!(udp.subkey(1), a, "re-derivation after a switch differs");
    }

    /// An AEAD-2022 packet must still round-trip after the cache was warmed by a
    /// different session.
    #[test]
    fn packet_round_trip_after_session_switch() {
        let mut udp = Udp2022::new(Method::Blake3Aes128Gcm, &PSK16).unwrap();

        // Warm the cache with another session.
        let warm = udp
            .encrypt_client_packet(0xaaa, 1, "127.0.0.1", 1, b"other")
            .unwrap();
        let _ = udp.decrypt_client_packet(&warm);

        let packet = udp
            .encrypt_client_packet(0xbbb, 1, "example.com", 8080, b"payload")
            .unwrap();
        let decoded = udp.decrypt_client_packet(&packet).unwrap();
        assert_eq!(decoded.client_session_id, 0xbbb);
        assert_eq!(decoded.host, "example.com");
        assert_eq!(decoded.port, 8080);
        assert_eq!(&decoded.payload[..], b"payload");
    }

    /// The ChaCha20 method seals with the psk, so it must never populate the
    /// subkey cache — its "subkey" would be wrong.
    #[test]
    fn chacha_method_round_trips() {
        let mut udp = Udp2022::new(Method::Blake3ChaCha20Poly1305, &PSK32).unwrap();
        let packet = udp
            .encrypt_server_packet(7, 3, 0x1234, "1.2.3.4", 53, b"reply")
            .unwrap();
        let decoded = udp.decrypt_server_packet(&packet).unwrap();
        assert_eq!(decoded.server_session_id, 7);
        assert_eq!(decoded.packet_id, 3);
        assert_eq!(decoded.client_session_id, 0x1234);
        assert_eq!(&decoded.payload[..], b"reply");

        assert!(
            udp.cached_subkey.is_none(),
            "chacha must not use the subkey cache"
        );
    }
}
