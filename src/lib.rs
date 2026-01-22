pub mod args;
pub mod cipher;
pub mod config;
pub mod listener;
pub mod local;
#[cfg(target_os = "linux")]
pub mod redir;
pub mod resolver;
pub mod server;
pub mod socks5;
pub mod util;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use futures_util::{AsyncRead, AsyncWrite};

use cipher::Cipher;

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(3);

const PAYLOAD_SIZE_MASK: usize = 0x3fff;

/// A stream wrapper that provides transparent encryption/decryption for async I/O operations.
///
/// This struct wraps an underlying async stream and applies encryption on writes and
/// decryption on reads using the provided cipher. It implements `AsyncRead` and `AsyncWrite`
/// to seamlessly integrate with async I/O operations.
pub(crate) struct CipherStream<'a, A: ?Sized> {
    /// The underlying async stream (e.g., TCP stream)
    stream: &'a mut A,
    /// Shared cipher instance for encryption/decryption operations
    cipher: Arc<Mutex<Cipher>>,
    /// Reader state for handling decryption during read operations
    reader: Reader,
    /// Writer state for handling encryption during write operations
    writer: Writer,
}

/// Reader state for decrypting data from the underlying stream.
///
/// Manages the buffer and state needed to read encrypted data from the stream,
/// decrypt it, and provide plaintext to the caller.
struct Reader {
    /// Buffer for storing encrypted data read from the stream
    buf: BytesMut,
    /// Whether the reader has been initialized (IV/salt read and decryptor initialized)
    inited: bool,
    /// Current read position within the buffer
    pos: usize,
    /// Capacity of valid data in the buffer
    cap: usize,
    /// AEAD reader for reading encrypted data
    aead: Option<AeadReader>,
}

/// Writer state for encrypting data before writing to the underlying stream.
///
/// Manages the buffer and state needed to encrypt plaintext data and write
/// the encrypted data (along with IV/salt) to the stream.
struct Writer {
    /// Buffer for storing encrypted data to be written to the stream
    buf: BytesMut,
    /// Whether the writer has been initialized (encryptor initialized and IV/salt written)
    inited: bool,
    /// Current write position within the buffer
    pos: usize,
    /// Capacity of valid data in the buffer
    cap: usize,
    /// Flag indicating whether the current write operation has completed reading from input
    read_done: bool,
    /// AEAD writer for writing encrypted data
    aead: Option<AeadWriter>,
}

impl<'a, A: ?Sized> CipherStream<'a, A> {
    pub fn new(cipher: Cipher, stream: &'a mut A) -> Self {
        let is_aead = cipher.is_aead();
        let tag_size = cipher.tag_size();
        let cipher = Arc::new(Mutex::new(cipher));
        CipherStream {
            stream,
            cipher,
            reader: Reader {
                buf: BytesMut::with_capacity(4096),
                inited: false,
                pos: 0,
                cap: 0,
                aead: if is_aead {
                    Some(AeadReader {
                        buf: BytesMut::with_capacity(4096),
                        pos: 0,
                        payload_size: 0,
                        tag_size,
                        state: AeadReaderState::PayloadSize,
                    })
                } else {
                    None
                },
            },
            writer: Writer {
                buf: BytesMut::with_capacity(4096),
                inited: false,
                pos: 0,
                cap: 0,
                read_done: false,
                aead: if is_aead {
                    Some(AeadWriter { tag_size })
                } else {
                    None
                },
            },
        }
    }
}

struct AeadReader {
    buf: BytesMut,
    pos: usize,
    tag_size: usize, // 16 bytes
    payload_size: usize,
    state: AeadReaderState,
}

struct AeadWriter {
    tag_size: usize, // 16 bytes
}

impl AeadWriter {
    /// Encrypt payload in AEAD format.
    /// Format: [encrypted payload length (2 bytes)][length tag (16 bytes)][encrypted payload][payload tag (16 bytes)]
    fn encrypt_payload(&self, payload: &[u8], cipher: &mut Cipher) -> io::Result<BytesMut> {
        let mut result = BytesMut::with_capacity(2 + self.tag_size + payload.len() + self.tag_size);
        result.resize(2 + self.tag_size + payload.len() + self.tag_size, 0u8);

        // Set payload length (first 2 bytes)
        result[..2].copy_from_slice(&u16::to_be_bytes(payload.len() as u16));

        // Encrypt payload length (first 2 bytes + tag)
        cipher.encrypt_in_place(&mut result[..2 + self.tag_size])?;

        // Copy payload data
        result[2 + self.tag_size..2 + self.tag_size + payload.len()].copy_from_slice(payload);

        // Encrypt payload (payload + tag)
        cipher.encrypt_in_place(&mut result[2 + self.tag_size..])?;

        Ok(result)
    }
}

enum AeadReaderState {
    PayloadSize,
    Payload,
}

impl AeadReader {
    fn poll_read_aead<A>(
        &mut self,
        cx: &mut Context<'_>,
        mut stream: &mut A,
        cipher: Arc<Mutex<Cipher>>,
    ) -> Poll<io::Result<BytesMut>>
    where
        A: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match self.state {
                AeadReaderState::PayloadSize => {
                    self.buf.resize(2 + self.tag_size, 0u8);
                    while self.pos < 2 + self.tag_size {
                        let n =
                            ready!(Pin::new(&mut stream).poll_read(cx, &mut self.buf[self.pos..]))?;
                        if n == 0 {
                            return Poll::Ready(Ok(BytesMut::new()));
                        }
                        self.pos += n;
                    }
                    let mut cipher = cipher.lock().unwrap();
                    cipher.decrypt_in_place(&mut self.buf[..2 + self.tag_size])?;
                    self.payload_size =
                        u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize & PAYLOAD_SIZE_MASK;
                    self.pos = 0;
                    self.state = AeadReaderState::Payload;
                }
                AeadReaderState::Payload => {
                    self.buf.resize(self.payload_size + self.tag_size, 0u8);
                    while self.pos < self.payload_size + self.tag_size {
                        let n =
                            ready!(Pin::new(&mut stream).poll_read(cx, &mut self.buf[self.pos..]))?;
                        if n == 0 {
                            return Poll::Ready(Ok(BytesMut::new()));
                        }
                        self.pos += n;
                    }
                    let mut cipher = cipher.lock().unwrap();
                    cipher.decrypt_in_place(&mut self.buf[..self.payload_size + self.tag_size])?;
                    self.pos = 0;
                    self.state = AeadReaderState::PayloadSize;
                    let result = self.buf.split_to(self.payload_size);
                    self.buf.clear();
                    return Poll::Ready(Ok(result));
                }
            }
        }
    }
}

impl<A> AsyncRead for CipherStream<'_, A>
where
    A: AsyncRead + Unpin + ?Sized,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        let reader = &mut me.reader;
        if !reader.inited {
            let mut cipher = me.cipher.lock().unwrap();
            while reader.pos < cipher.iv_or_salt_len() {
                let n = ready!(Pin::new(&mut me.stream)
                    .poll_read(cx, &mut cipher.decrypt_iv_or_salt_mut()[reader.pos..]))?;
                if n == 0 {
                    return Poll::Ready(Ok(0));
                }
                reader.pos += n;
            }
            cipher.init_decrypt();
            reader.inited = true;
            reader.pos = 0;
            reader.cap = 0;
        }

        loop {
            // if our buffer is empty, then we need to read some data to continue.
            if reader.pos < reader.cap {
                let n = (reader.cap - reader.pos).min(buf.len());
                buf[..n].copy_from_slice(&reader.buf[reader.pos..reader.pos + n]);
                reader.pos += n;
                return Poll::Ready(Ok(n));
            }

            // if we are using AEAD, then we need to read the data from the stream
            if let Some(aead) = reader.aead.as_mut() {
                let data = ready!(aead.poll_read_aead(cx, &mut me.stream, me.cipher.clone()))?;
                if data.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                reader.pos = 0;
                reader.cap = data.len();
                reader.buf = data;
                continue;
            }
            reader.buf.resize(4096, 0u8);
            let n = ready!(Pin::new(&mut me.stream).poll_read(cx, &mut reader.buf[..]))?;
            if n == 0 {
                return Poll::Ready(Ok(0));
            }
            reader.pos = 0;
            reader.cap = n;
            let mut cipher = me.cipher.lock().unwrap();
            cipher.decrypt_in_place(&mut reader.buf[..n])?;
        }
    }
}

impl<A> AsyncWrite for CipherStream<'_, A>
where
    A: AsyncWrite + Unpin + ?Sized,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        let writer = &mut me.writer;
        if !writer.inited {
            let mut cipher = me.cipher.lock().unwrap();
            cipher.init_encrypt();
            writer.inited = true;

            let n = cipher.iv_or_salt_len();
            writer.cap = n;
            writer.buf.resize(n, 0u8);
            writer.buf[..n].copy_from_slice(cipher.encrypt_iv_or_salt());
        }

        loop {
            // If our buffer has some data, let's write it out!
            while writer.pos < writer.cap {
                let i =
                    ready!(Pin::new(&mut me.stream)
                        .poll_write(cx, &writer.buf[writer.pos..writer.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    writer.pos += i;
                }
            }

            if writer.pos == writer.cap && writer.read_done {
                writer.read_done = false;
                return Poll::Ready(Ok(buf.len()));
            }

            let mut cipher = me.cipher.lock().unwrap();
            let data = if let Some(aead) = writer.aead.as_ref() {
                // AEAD: encrypt payload with format [encrypted length][length tag][encrypted payload][payload tag]
                aead.encrypt_payload(buf, &mut cipher)?
            } else {
                // Non-AEAD: copy data first, then encrypt in place
                let mut data = BytesMut::from(buf);
                cipher.encrypt_in_place(&mut data)?;
                data
            };
            writer.pos = 0;
            writer.cap = data.len();
            writer.buf = data;
            writer.read_done = true;
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}
