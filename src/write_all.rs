use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::cipher::Cipher;

use slings::AsyncWrite;

pub struct EncryptWriteAll<'a, W: ?Sized> {
    cipher: Rc<RefCell<Cipher>>,
    writer: &'a mut W,
    buf: &'a [u8],
}

pub fn write_all<'a, W>(
    cipher: Rc<RefCell<Cipher>>,
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
        let mut cipher = me.cipher.borrow_mut();
        let mut data = if cipher.enc.is_none() {
            cipher.init_encrypt();
            cipher.iv.clone()
        } else {
            vec![]
        };

        data.extend_from_slice(&me.buf);
        let data_len = data.len();
        if data_len > me.buf.len() {
            cipher.encrypt(&mut data[data_len - me.buf.len()..]);
        }

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
