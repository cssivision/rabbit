use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use awak::io::AsyncWrite;
use parking_lot::Mutex;

use crate::cipher::Cipher;

pub struct EncryptWriteAll<'a, W: ?Sized> {
    cipher: Arc<Mutex<Cipher>>,
    writer: &'a mut W,
    buf: &'a [u8],
    encrypt_buf: Vec<u8>,
}

pub fn write_all<'a, W>(
    cipher: Arc<Mutex<Cipher>>,
    writer: &'a mut W,
    buf: &'a [u8],
) -> EncryptWriteAll<'a, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    EncryptWriteAll {
        cipher,
        writer,
        buf,
        encrypt_buf: vec![],
    }
}

impl<W> Future for EncryptWriteAll<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        let mut cipher = me.cipher.lock();
        if me.encrypt_buf.is_empty() {
            let mut data = if cipher.enc.is_none() {
                cipher.init_encrypt();
                cipher.iv.clone()
            } else {
                vec![]
            };

            data.extend_from_slice(me.buf);
            let data_len = data.len();
            if data_len > me.buf.len() {
                cipher.encrypt(&mut data[data_len - me.buf.len()..]);
            }
            me.encrypt_buf = data;
        }

        while !me.encrypt_buf.is_empty() {
            let n = ready!(Pin::new(&mut me.writer).poll_write(cx, &me.encrypt_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            me.encrypt_buf.drain(0..n);
        }
        Poll::Ready(Ok(()))
    }
}
