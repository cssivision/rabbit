use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::cipher::Cipher;
use crate::util::{eof, other};

use awak::io::AsyncRead;

pub struct DecryptReadExact<'a, A: ?Sized> {
    cipher: Arc<Mutex<Cipher>>,
    reader: &'a mut A,
    buf: &'a mut [u8],
    pos: usize,
}

pub fn read_exact<'a, A>(
    cipher: Arc<Mutex<Cipher>>,
    reader: &'a mut A,
    buf: &'a mut [u8],
) -> DecryptReadExact<'a, A>
where
    A: AsyncRead + Unpin + ?Sized,
{
    DecryptReadExact {
        cipher,
        reader,
        buf,
        pos: 0,
    }
}

impl<A> Future for DecryptReadExact<'_, A>
where
    A: AsyncRead + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        let mut cipher = me.cipher.lock().unwrap();
        if cipher.dec.is_none() {
            let mut iv = vec![0u8; cipher.iv_len];
            while me.pos < iv.len() {
                let n = ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut iv[me.pos..]))?;
                me.pos += n;
                if n == 0 {
                    return Err(eof()).into();
                }
            }

            me.pos = 0;
            cipher.iv = iv.clone();
            cipher.init_decrypt(&iv);
        };

        // if our buffer is empty, then we need to read some data to continue.
        while me.pos < me.buf.len() {
            let n = ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut me.buf[me.pos..]))?;
            me.pos += n;
            if n == 0 {
                return Err(eof()).into();
            }
        }

        let plain_data = match cipher.decrypt(&me.buf[..me.buf.len()]) {
            Some(b) => b,
            None => return Err(other("decrypt error")).into(),
        };

        let copy_len = me.buf.len();
        me.buf[..copy_len].copy_from_slice(&plain_data[..copy_len]);
        Poll::Ready(Ok(me.pos))
    }
}
