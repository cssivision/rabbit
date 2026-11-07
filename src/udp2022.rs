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

use std::convert::TryFrom;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use aes_gcm::aead::{AeadInOut, Buffer};
use cipher::{
    array::Array,
    consts::{U12, U24},
};

use crate::cipher::Method;
use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};
use crate::util::{derive_blake3_subkey, generate_raw_addr};

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
    pub payload: Vec<u8>,
}

/// A decrypted server -> client packet.
pub struct ServerPacket {
    pub server_session_id: u64,
    pub packet_id: u64,
    pub client_session_id: u64,
    pub host: String,
    pub port: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
enum UdpAead {
    Aes128Gcm,
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl UdpAead {
    fn of(method: Method) -> Option<UdpAead> {
        match method {
            Method::Blake3Aes128Gcm => Some(UdpAead::Aes128Gcm),
            Method::Blake3Aes256Gcm => Some(UdpAead::Aes256Gcm),
            Method::Blake3ChaCha20Poly1305 => Some(UdpAead::XChaCha20Poly1305),
            _ => None,
        }
    }

    fn key_len(&self) -> usize {
        match self {
            UdpAead::Aes128Gcm => 16,
            UdpAead::Aes256Gcm => 32,
            UdpAead::XChaCha20Poly1305 => 32,
        }
    }

    fn is_chacha(&self) -> bool {
        matches!(self, UdpAead::XChaCha20Poly1305)
    }
}

/// 2022 UDP cipher state: the pre-shared key plus the method.
pub struct Udp2022 {
    aead: UdpAead,
    psk: Vec<u8>,
}

impl Udp2022 {
    pub fn new(method: Method, psk: &[u8]) -> io::Result<Udp2022> {
        let aead = UdpAead::of(method).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "not an AEAD 2022 method")
        })?;
        if psk.len() != aead.key_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "key length must be {} for 2022 AEAD ciphers",
                    aead.key_len()
                ),
            ));
        }
        Ok(Udp2022 {
            aead,
            psk: psk.to_vec(),
        })
    }

    /// Session subkey: `blake3::derive_key(psk || session_id_be)`.
    fn subkey(&self, session_id: u64) -> Vec<u8> {
        let mut key = derive_blake3_subkey(&self.psk, &session_id.to_be_bytes());
        key.truncate(self.aead.key_len());
        key
    }

    /// Seal `plaintext` in place, appending the 16 byte authentication tag.
    fn seal(&self, session_id: u64, nonce: &[u8], plaintext: Vec<u8>) -> io::Result<Vec<u8>> {
        let mut buffer = plaintext;
        let result = match self.aead {
            UdpAead::Aes128Gcm => {
                let key = self.subkey(session_id);
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let nonce = Array::<u8, U12>::try_from(nonce)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
                cipher.encrypt_in_place(&nonce, &[], &mut buffer as &mut dyn Buffer)
            }
            UdpAead::Aes256Gcm => {
                let key = self.subkey(session_id);
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let nonce = Array::<u8, U12>::try_from(nonce)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
                cipher.encrypt_in_place(&nonce, &[], &mut buffer as &mut dyn Buffer)
            }
            UdpAead::XChaCha20Poly1305 => {
                let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&self.psk)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let nonce = Array::<u8, U24>::try_from(nonce)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
                cipher.encrypt_in_place(&nonce, &[], &mut buffer as &mut dyn Buffer)
            }
        };
        match result {
            Ok(()) => Ok(buffer),
            Err(e) => Err(io::Error::other(format!("AEAD encryption failed: {e}"))),
        }
    }

    /// Open a sealed body, stripping the authentication tag.
    fn open(&self, session_id: u64, nonce: &[u8], ciphertext: Vec<u8>) -> io::Result<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "packet shorter than the AEAD tag",
            ));
        }
        let mut buffer = ciphertext;
        let result = match self.aead {
            UdpAead::Aes128Gcm => {
                let key = self.subkey(session_id);
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let nonce = Array::<u8, U12>::try_from(nonce)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
                cipher.decrypt_in_place(&nonce, &[], &mut buffer as &mut dyn Buffer)
            }
            UdpAead::Aes256Gcm => {
                let key = self.subkey(session_id);
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let nonce = Array::<u8, U12>::try_from(nonce)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
                cipher.decrypt_in_place(&nonce, &[], &mut buffer as &mut dyn Buffer)
            }
            UdpAead::XChaCha20Poly1305 => {
                let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&self.psk)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let nonce = Array::<u8, U24>::try_from(nonce)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
                cipher.decrypt_in_place(&nonce, &[], &mut buffer as &mut dyn Buffer)
            }
        };
        match result {
            Ok(()) => Ok(buffer),
            Err(e) => Err(io::Error::other(format!(
                "AEAD decryption failed (authentication failed): {e}"
            ))),
        }
    }

    /// Decrypt a client -> server datagram.
    pub fn decrypt_client_packet(&self, packet: &[u8]) -> io::Result<ClientPacket> {
        let (session_id, packet_id, plaintext) = self.open_packet(packet)?;
        let mut cursor = Cursor::new(&plaintext);
        if self.aead.is_chacha() {
            let body_session_id = cursor.u64()?;
            let body_packet_id = cursor.u64()?;
            if body_session_id != session_id || body_packet_id != packet_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session id or packet id mismatch in packet header",
                ));
            }
        }
        let socket_type = cursor.u8()?;
        if socket_type != CLIENT_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid socket type {socket_type:#x}, expecting {CLIENT_TYPE:#x}"),
            ));
        }
        cursor.timestamp()?;
        cursor.skip_padding()?;
        let (host, port) = cursor.address()?;

        Ok(ClientPacket {
            client_session_id: session_id,
            packet_id,
            host,
            port,
            payload: cursor.remaining().to_vec(),
        })
    }

    /// Decrypt a server -> client datagram.
    pub fn decrypt_server_packet(&self, packet: &[u8]) -> io::Result<ServerPacket> {
        let (session_id, packet_id, plaintext) = self.open_packet(packet)?;
        let mut cursor = Cursor::new(&plaintext);
        if self.aead.is_chacha() {
            let body_session_id = cursor.u64()?;
            let body_packet_id = cursor.u64()?;
            if body_session_id != session_id || body_packet_id != packet_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session id or packet id mismatch in packet header",
                ));
            }
        }
        let socket_type = cursor.u8()?;
        if socket_type != SERVER_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid socket type {socket_type:#x}, expecting {SERVER_TYPE:#x}"),
            ));
        }
        cursor.timestamp()?;
        let client_session_id = cursor.u64()?;
        cursor.skip_padding()?;
        let (host, port) = cursor.address()?;

        Ok(ServerPacket {
            server_session_id: session_id,
            packet_id,
            client_session_id,
            host,
            port,
            payload: cursor.remaining().to_vec(),
        })
    }

    /// Build a client -> server datagram.
    pub fn encrypt_client_packet(
        &self,
        client_session_id: u64,
        packet_id: u64,
        host: &str,
        port: u16,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut body = Vec::with_capacity(64 + payload.len());
        if self.aead.is_chacha() {
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
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_server_packet(
        &self,
        server_session_id: u64,
        packet_id: u64,
        client_session_id: u64,
        host: &str,
        port: u16,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut body = Vec::with_capacity(64 + payload.len());
        if self.aead.is_chacha() {
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
    fn seal_packet(&self, session_id: u64, packet_id: u64, body: Vec<u8>) -> io::Result<Vec<u8>> {
        if self.aead.is_chacha() {
            let mut nonce = vec![0u8; CHACHA_NONCE_LEN];
            rand::fill(&mut nonce[..]);
            let body = self.seal(session_id, &nonce, body)?;
            let mut packet = nonce;
            packet.extend_from_slice(&body);
            return Ok(packet);
        }

        let mut header = [0u8; AES_HEADER_LEN];
        header[..8].copy_from_slice(&session_id.to_be_bytes());
        header[8..].copy_from_slice(&packet_id.to_be_bytes());
        let nonce = header[4..16].to_vec();
        self.encrypt_header(&mut header)?;
        let body = self.seal(session_id, &nonce, body)?;

        let mut packet = header.to_vec();
        packet.extend_from_slice(&body);
        Ok(packet)
    }

    fn encrypt_header(&self, header: &mut [u8; AES_HEADER_LEN]) -> io::Result<()> {
        match self.aead {
            UdpAead::Aes128Gcm => {
                let cipher = Aes128::new_from_slice(&self.psk)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let block = <&mut Block>::try_from(&mut header[..])
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block"))?;
                cipher.encrypt_block(block);
            }
            _ => {
                let cipher = Aes256::new_from_slice(&self.psk)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let block = <&mut Block>::try_from(&mut header[..])
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block"))?;
                cipher.encrypt_block(block);
            }
        }
        Ok(())
    }

    fn decrypt_header(&self, header: &mut [u8; AES_HEADER_LEN]) -> io::Result<()> {
        match self.aead {
            UdpAead::Aes128Gcm => {
                let cipher = Aes128::new_from_slice(&self.psk)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let block = <&mut Block>::try_from(&mut header[..])
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block"))?;
                cipher.decrypt_block(block);
            }
            _ => {
                let cipher = Aes256::new_from_slice(&self.psk)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let block = <&mut Block>::try_from(&mut header[..])
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block"))?;
                cipher.decrypt_block(block);
            }
        }
        Ok(())
    }

    /// Decrypt the envelope and return `(session_id, packet_id, plaintext_body)`.
    fn open_packet(&self, packet: &[u8]) -> io::Result<(u64, u64, Vec<u8>)> {
        if self.aead.is_chacha() {
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
            return Ok((u64::from_be_bytes(sid), u64::from_be_bytes(pid), body));
        }

        if packet.len() < AES_HEADER_LEN + 16 + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "packet too short",
            ));
        }
        let mut header = [0u8; AES_HEADER_LEN];
        header.copy_from_slice(&packet[..AES_HEADER_LEN]);
        self.decrypt_header(&mut header)?;
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&header[..8]);
        let mut pid = [0u8; 8];
        pid.copy_from_slice(&header[8..]);
        let nonce = header[4..16].to_vec();

        let session_id = u64::from_be_bytes(sid);
        let body = self.open(session_id, &nonce, packet[AES_HEADER_LEN..].to_vec())?;
        Ok((session_id, u64::from_be_bytes(pid), body))
    }
}

/// Sliding replay window over 64-bit packet ids, same shape as the WireGuard
/// counter window used by shadowsocks-rust.
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

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Cursor<'a> {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.buf.len() < self.pos + n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "packet too short",
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let mut b = [0u8; 2];
        b.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(b))
    }

    fn u64(&mut self) -> io::Result<u64> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(b))
    }

    fn timestamp(&mut self) -> io::Result<u64> {
        let ts = self.u64()?;
        let diff = now().abs_diff(ts);
        if diff > TIMESTAMP_MAX_DIFF {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid timestamp, clock skew {diff}s"),
            ));
        }
        Ok(ts)
    }

    fn skip_padding(&mut self) -> io::Result<()> {
        let n = self.u16()? as usize;
        self.take(n)?;
        Ok(())
    }

    fn address(&mut self) -> io::Result<(String, u16)> {
        let atyp = self.u8()?;
        let host = match atyp {
            TYPE_IPV4 => {
                let mut b = [0u8; 4];
                b.copy_from_slice(self.take(4)?);
                Ipv4Addr::from(b).to_string()
            }
            TYPE_IPV6 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(self.take(16)?);
                Ipv6Addr::from(b).to_string()
            }
            TYPE_DOMAIN => {
                let len = self.u8()? as usize;
                String::from_utf8(self.take(len)?.to_vec())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported address type {atyp:#x}"),
                ))
            }
        };
        let port = self.u16()?;
        Ok((host, port))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}
