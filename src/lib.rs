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
pub mod udp2022;
pub mod udp_legacy;
pub mod util;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use futures_util::{AsyncRead, AsyncWrite};

use cipher::Cipher;
use util::COPY_BUFFER_SIZE;

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(3);

const MAX_PAYLOAD_SIZE: usize = 0xffff;
const MAX_MESSAGE_AGE_SECONDS: u64 = 30;

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
    /// Largest payload a single record may carry, cached from the cipher
    max_payload: usize,
    /// AEAD writer for writing encrypted data
    aead: Option<AeadWriter>,
}

enum ServerType {
    Local,
    Remote,
}

impl<'a, A: ?Sized> CipherStream<'a, A> {
    /// Create a new cipher stream for local server.
    pub fn local(cipher: Cipher, stream: &'a mut A) -> Self {
        Self::new(cipher, stream, ServerType::Local)
    }

    /// Create a new cipher stream for remote server.
    pub fn remote(cipher: Cipher, stream: &'a mut A) -> Self {
        Self::new(cipher, stream, ServerType::Remote)
    }

    fn new(cipher: Cipher, stream: &'a mut A, server_type: ServerType) -> Self {
        let (s1, s2) = match server_type {
            ServerType::Local => (StreamType::Response, StreamType::Request),
            ServerType::Remote => (StreamType::Request, StreamType::Response),
        };
        let is_aead = cipher.is_aead();
        let tag_size = cipher.tag_size();
        let is_aead2022 = cipher.is_aead2022();
        let seed_size = cipher.seed_len();
        let max_payload = cipher.max_payload_size();
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
                        tag_size,
                        seed_size,
                        state: AeadReaderState::Header,
                        is_aead2022,
                        stream_type: s1,
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
                max_payload,
                aead: if is_aead {
                    Some(AeadWriter {
                        tag_size,
                        state: AeadWriterState::Header,
                        is_aead2022,
                        stream_type: s2,
                    })
                } else {
                    None
                },
            },
        }
    }
}

/// Stream type.
#[derive(Copy, Clone, PartialEq, Debug)]
enum StreamType {
    Request = 0,
    Response = 1,
}

/// AEAD reader for decrypting data in AEAD format.
struct AeadReader {
    tag_size: usize,
    state: AeadReaderState,
    // aead2022 specific
    seed_size: usize,
    is_aead2022: bool,
    stream_type: StreamType,
}

/// AEAD writer state.
enum AeadWriterState {
    Header,
    Payload,
}

/// AEAD writer for encrypting data in AEAD format.
struct AeadWriter {
    tag_size: usize,
    state: AeadWriterState,
    // aead2022 specific
    is_aead2022: bool,
    stream_type: StreamType,
}

impl AeadWriter {
    /// Append one encrypted AEAD-2022 header to `out`.
    fn write_aead2022_header(
        &mut self,
        out: &mut BytesMut,
        payload_len: usize,
        cipher: &mut Cipher,
    ) -> io::Result<()> {
        let start = out.len();
        out.put_u8(self.stream_type as u8);
        out.put_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        if self.stream_type == StreamType::Response {
            out.put_slice(cipher.decrypt_seed().as_bytes());
        }
        out.put_u16(payload_len as u16);
        // Only the tag area needs clearing: the header itself is fully written above.
        out.resize(out.len() + self.tag_size, 0u8);
        cipher.encrypt_in_place(&mut out[start..])?;
        Ok(())
    }

    /// Encrypt payload in AEAD format and append it to `out`.
    /// Format: [encrypted payload length (2 bytes)][length tag (16 bytes)][encrypted payload][payload tag (16 bytes)]
    fn encrypt_payload(
        &mut self,
        out: &mut BytesMut,
        payload: &[u8],
        cipher: &mut Cipher,
    ) -> io::Result<()> {
        // An AEAD-2022 header already carries the payload length, so the first
        // record of such a stream has no separate length chunk.
        let mut with_length = true;
        if let AeadWriterState::Header = self.state {
            if self.is_aead2022 {
                self.write_aead2022_header(out, payload.len(), cipher)?;
                with_length = false;
            }
            self.state = AeadWriterState::Payload;
        }

        if with_length {
            let start = out.len();
            out.put_u16(payload.len() as u16);
            out.resize(out.len() + self.tag_size, 0u8);
            cipher.encrypt_in_place(&mut out[start..])?;
        }

        let start = out.len();
        out.put_slice(payload);
        out.resize(out.len() + self.tag_size, 0u8);
        cipher.encrypt_in_place(&mut out[start..])?;
        Ok(())
    }
}

enum AeadReaderState {
    Header,
    Length,
    Payload(usize),
}

impl AeadReader {
    /// Parse an AEAD-2022 header that was decrypted in place (tag removed).
    fn parse_aead2022_header(&self, header: &[u8], request_seed: &[u8]) -> io::Result<usize> {
        let stream_type = header[0];
        if stream_type != self.stream_type as u8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream type mismatch",
            ));
        }
        let timestamp = u64::from_be_bytes([
            header[1], header[2], header[3], header[4], header[5], header[6], header[7], header[8],
        ]);
        if timestamp.abs_diff(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ) > MAX_MESSAGE_AGE_SECONDS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message must with over 30 seconds",
            ));
        }
        let mut rest = &header[9..];
        if stream_type == StreamType::Response as u8 {
            let (seed, tail) = rest.split_at(self.seed_size);
            if seed != request_seed {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request salt invalid",
                ));
            }
            rest = tail;
        }
        let size = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if size > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload size is too large",
            ));
        }
        Ok(size)
    }

    /// Read one record into `buf`, leaving its decrypted payload there.
    ///
    /// Returns the payload length, or 0 when the underlying stream ended before
    /// a full record could be read.
    fn poll_read_aead<A>(
        &mut self,
        cx: &mut Context<'_>,
        mut stream: &mut A,
        cipher: Arc<Mutex<Cipher>>,
        buf: &mut BytesMut,
    ) -> Poll<io::Result<usize>>
    where
        A: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match self.state {
                AeadReaderState::Header => {
                    if !self.is_aead2022 {
                        self.state = AeadReaderState::Length;
                        continue;
                    }
                    let header_size = match self.stream_type {
                        StreamType::Request => 11 + self.tag_size,
                        StreamType::Response => 11 + self.seed_size + self.tag_size,
                    };
                    let n = ready!(poll_read_exact(&mut stream, cx, buf, header_size))?;
                    if n < header_size {
                        return Poll::Ready(Ok(0));
                    }
                    let mut cipher = cipher.lock().unwrap();
                    cipher.decrypt_in_place(&mut buf[..header_size])?;
                    let size = self.parse_aead2022_header(
                        &buf[..header_size - self.tag_size],
                        cipher.encrypt_seed().as_bytes(),
                    )?;
                    buf.clear();
                    self.state = AeadReaderState::Payload(size);
                }
                AeadReaderState::Length => {
                    let length_size = 2 + self.tag_size;
                    let n = ready!(poll_read_exact(&mut stream, cx, buf, length_size))?;
                    if n < length_size {
                        return Poll::Ready(Ok(0));
                    }
                    let mut cipher = cipher.lock().unwrap();
                    cipher.decrypt_in_place(&mut buf[..length_size])?;
                    let size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if size > MAX_PAYLOAD_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "payload size is too large",
                        )));
                    }
                    buf.clear();
                    self.state = AeadReaderState::Payload(size);
                }
                AeadReaderState::Payload(size) => {
                    let record_size = size + self.tag_size;
                    let n = ready!(poll_read_exact(&mut stream, cx, buf, record_size))?;
                    if n < record_size {
                        return Poll::Ready(Ok(0));
                    }
                    let mut cipher = cipher.lock().unwrap();
                    cipher.decrypt_in_place(&mut buf[..record_size])?;
                    drop(cipher);
                    buf.truncate(size);
                    self.state = AeadReaderState::Length;
                    return Poll::Ready(Ok(size));
                }
            }
        }
    }
}

/// Read up to `len` bytes into the unused tail of `buf`, without zero-filling it.
///
/// Returns the number of bytes appended.
fn poll_read_uninit<A>(
    stream: &mut A,
    cx: &mut Context<'_>,
    buf: &mut BytesMut,
    len: usize,
) -> Poll<io::Result<usize>>
where
    A: AsyncRead + Unpin + ?Sized,
{
    if len == 0 {
        return Poll::Ready(Ok(0));
    }
    buf.reserve(len);
    // SAFETY: `chunk_mut` yields at least `len` bytes of spare capacity, and the
    // stream only reports bytes it actually wrote into that slice.
    let spare = unsafe { std::slice::from_raw_parts_mut(buf.chunk_mut().as_mut_ptr(), len) };
    let n = ready!(Pin::new(stream).poll_read(cx, spare))?;
    if n > 0 {
        // SAFETY: the first `n` bytes of the spare capacity were just initialised.
        unsafe { buf.advance_mut(n) };
    }
    Poll::Ready(Ok(n))
}

/// Read exactly `len` bytes into `buf`; stops early on EOF.
fn poll_read_exact<A>(
    stream: &mut A,
    cx: &mut Context<'_>,
    buf: &mut BytesMut,
    len: usize,
) -> Poll<io::Result<usize>>
where
    A: AsyncRead + Unpin + ?Sized,
{
    while buf.len() < len {
        let want = len - buf.len();
        let n = ready!(poll_read_uninit(stream, cx, buf, want))?;
        if n == 0 {
            break;
        }
    }
    Poll::Ready(Ok(buf.len()))
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
        if !me.reader.inited {
            // `pos` doubles as the progress of the seed read: this method may
            // return `Pending` in the middle of it, and the seed must not be
            // reread from the start on the next poll.
            let mut cipher = me.cipher.lock().unwrap();
            while me.reader.pos < cipher.seed_len() {
                let n = ready!(Pin::new(&mut me.stream).poll_read(
                    cx,
                    &mut cipher.decrypt_seed_mut().as_mut_bytes()[me.reader.pos..]
                ))?;
                if n == 0 {
                    return Poll::Ready(Ok(0));
                }
                me.reader.pos += n;
            }
            cipher.init_decrypt();
            me.reader.inited = true;
            me.reader.pos = 0;
            me.reader.cap = 0;
        }
        loop {
            let CipherStream {
                reader,
                stream,
                cipher,
                ..
            } = me;
            if reader.pos < reader.cap {
                let n = std::cmp::min(buf.len(), reader.cap - reader.pos);
                buf[..n].copy_from_slice(&reader.buf[reader.pos..reader.pos + n]);
                reader.pos += n;
                if reader.pos == reader.cap {
                    reader.buf.clear();
                    reader.pos = 0;
                    reader.cap = 0;
                }
                return Poll::Ready(Ok(n));
            }
            let Reader {
                buf: read_buf,
                aead,
                pos,
                cap,
                inited: _,
            } = reader;
            let len = match aead {
                Some(aead) => {
                    ready!(aead.poll_read_aead(cx, &mut *stream, cipher.clone(), read_buf))?
                }
                None => {
                    read_buf.clear();
                    // Stream ciphers put no framing on the wire, so reading a
                    // large chunk costs nothing extra and keeps the relay from
                    // copying 4 KiB at a time.
                    let n = ready!(poll_read_uninit(
                        &mut *stream,
                        cx,
                        read_buf,
                        COPY_BUFFER_SIZE
                    ))?;
                    if n == 0 {
                        return Poll::Ready(Ok(0));
                    }
                    let mut cipher = cipher.lock().unwrap();
                    cipher.decrypt_in_place(&mut read_buf[..n])?;
                    n
                }
            };
            if len == 0 {
                return Poll::Ready(Ok(0));
            }
            *pos = 0;
            *cap = len;
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
        // One write may carry more than one record, but a single record cannot
        // exceed the cipher's payload limit: accept only what fits.
        let max_payload = me.writer.max_payload;
        let buf = &buf[..buf.len().min(max_payload)];
        let writer = &mut me.writer;
        // The first encrypted chunk must carry the seed as a prefix, in the same
        // write: peers read the whole header chunk (seed included) with a
        // single read call. This is known before any state changes, and the
        // first call always reaches the encrypt step below because `cap` stays
        // 0 until a chunk has been built.
        let first_chunk = !writer.inited;

        loop {
            // If our buffer has some data, let's write it out!
            while writer.pos < writer.cap {
                let i = ready!(
                    Pin::new(&mut me.stream).poll_write(cx, &writer.buf[writer.pos..writer.cap])
                )?;
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

            let Writer {
                buf: out,
                aead,
                pos,
                cap,
                read_done,
                inited,
                ..
            } = writer;
            let mut cipher = me.cipher.lock().unwrap();
            if first_chunk {
                cipher.init_encrypt();
                *inited = true;
            }
            out.clear();
            if first_chunk {
                out.put_slice(cipher.encrypt_seed().as_bytes());
            }
            let seed_len = if first_chunk { cipher.seed_len() } else { 0 };
            match aead {
                // AEAD: append [encrypted length][length tag][encrypted payload][payload tag]
                Some(aead) => aead.encrypt_payload(out, buf, &mut cipher)?,
                // Non-AEAD: append the plaintext and encrypt it in place.
                None => {
                    out.put_slice(buf);
                    cipher.encrypt_in_place(&mut out[seed_len..])?;
                }
            }
            *pos = 0;
            *cap = out.len();
            *read_done = true;
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}
