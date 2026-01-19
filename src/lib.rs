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

use futures_util::{AsyncRead, AsyncWrite};

use cipher::Cipher;

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(3);

pub(crate) struct CipherStream<'a, A: ?Sized> {
    stream: &'a mut A,
    cipher: Arc<Mutex<Cipher>>,
    reader: Reader,
    writer: Writer,
}

struct Reader {
    buf: Vec<u8>,
    inited: bool,
    pos: usize,
    cap: usize,
}

struct Writer {
    buf: Vec<u8>,
    inited: bool,
    pos: usize,
    cap: usize,
    read_done: bool,
}

impl<'a, A: ?Sized> CipherStream<'a, A> {
    pub fn new(cipher: Arc<Mutex<Cipher>>, stream: &'a mut A) -> Self {
        CipherStream {
            stream,
            cipher,
            reader: Reader {
                buf: vec![0u8; 4096],
                inited: false,
                pos: 0,
                cap: 0,
            },
            writer: Writer {
                buf: Vec::with_capacity(4096),
                inited: false,
                pos: 0,
                cap: 0,
                read_done: false,
            },
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
            while reader.pos < cipher.iv_len() {
                let n = ready!(
                    Pin::new(&mut me.stream).poll_read(cx, &mut cipher.iv_mut()[reader.pos..])
                )?;
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
            let n = ready!(Pin::new(&mut me.stream).poll_read(cx, &mut reader.buf[..]))?;
            if n == 0 {
                return Poll::Ready(Ok(0));
            }
            reader.pos = 0;
            reader.cap = n;
            let mut cipher = me.cipher.lock().unwrap();
            cipher.decrypt_in_place(&mut reader.buf[..n]);
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

            let n = cipher.iv_len();
            writer.cap = n;
            writer.buf.resize(n, 0u8);
            writer.buf[..n].copy_from_slice(cipher.iv());
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
                return Poll::Ready(Ok(writer.cap));
            }

            let n = buf.len();
            writer.pos = 0;
            writer.cap = n;
            writer.buf.resize(n, 0u8);
            writer.buf[..n].copy_from_slice(buf);
            let mut cipher = me.cipher.lock().unwrap();
            cipher.encrypt_in_place(&mut writer.buf[..n]);
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
