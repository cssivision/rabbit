use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use log::error;

use crate::cipher::Cipher;
use crate::util::other;

use tokio::io::AsyncWrite;

pub struct EncryptWriteAll<'a, W: ?Sized> {
    cipher: Arc<Mutex<Cipher>>,
    writer: &'a mut W,
    buf: &'a [u8],
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
    }
}

impl<W> Future for EncryptWriteAll<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        let mut cipher = me.cipher.lock().unwrap();
        let mut data = if cipher.enc.is_none() {
            cipher.init_encrypt();
            cipher.iv.clone()
        } else {
            vec![]
        };

        let cipher_buf = match cipher.encrypt(&me.buf) {
            Some(b) => Vec::from(&b[..me.buf.len()]),
            None => {
                error!("encrypt error");
                return Err(other("encrypt error!")).into();
            }
        };

        data.extend_from_slice(&cipher_buf);

        while !data.is_empty() {
            let n = ready!(Pin::new(&mut me.writer).poll_write(cx, &data))?;
            let (_, rest) = data.split_at(n);
            data = rest.to_vec();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(Ok(()))
    }
}
