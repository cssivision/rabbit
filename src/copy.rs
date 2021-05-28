use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::cipher::Cipher;
use crate::util::eof;

use awak::io::{AsyncRead, AsyncWrite};
use parking_lot::Mutex;

pub struct DecryptReadCopy<'a, R: ?Sized, W: ?Sized> {
    cipher: Arc<Mutex<Cipher>>,
    reader: &'a mut R,
    read_done: bool,
    writer: &'a mut W,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl<'a, R: ?Sized, W: ?Sized> DecryptReadCopy<'a, R, W> {
    pub fn amt(&self) -> u64 {
        self.amt
    }
}

pub fn decrypt_copy<'a, R, W>(
    cipher: Arc<Mutex<Cipher>>,
    reader: &'a mut R,
    writer: &'a mut W,
) -> DecryptReadCopy<'a, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    DecryptReadCopy {
        cipher,
        reader,
        read_done: false,
        writer,
        amt: 0,
        pos: 0,
        cap: 0,
        buf: Box::new([0; 1024 * 64]),
    }
}

impl<R, W> Future for DecryptReadCopy<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let me = &mut *self;
        let mut cipher = me.cipher.lock();
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
        }

        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if me.pos == me.cap && !me.read_done {
                let n = ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut me.buf))?;
                if n == 0 {
                    me.read_done = true;
                } else {
                    cipher.decrypt(&mut me.buf[..n]);

                    me.pos = 0;
                    me.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while me.pos < me.cap {
                let i = ready!(Pin::new(&mut *me.writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    me.pos += i;
                    me.amt += i as u64;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if me.pos == me.cap && me.read_done {
                ready!(Pin::new(&mut *me.writer).poll_flush(cx))?;
                return Poll::Ready(Ok(me.amt));
            }
        }
    }
}

pub struct EncryptWriteCopy<'a, R: ?Sized, W: ?Sized> {
    cipher: Arc<Mutex<Cipher>>,
    reader: &'a mut R,
    read_done: bool,
    writer: &'a mut W,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl<'a, R: ?Sized, W: ?Sized> EncryptWriteCopy<'a, R, W> {
    pub fn amt(&self) -> u64 {
        self.amt
    }
}

pub fn encrypt_copy<'a, R, W>(
    cipher: Arc<Mutex<Cipher>>,
    reader: &'a mut R,
    writer: &'a mut W,
) -> EncryptWriteCopy<'a, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    EncryptWriteCopy {
        cipher,
        reader,
        read_done: false,
        writer,
        amt: 0,
        pos: 0,
        cap: 0,
        buf: Box::new([0; 1024 * 64]),
    }
}

impl<R, W> Future for EncryptWriteCopy<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let me = &mut *self;
        let mut cipher = me.cipher.lock();
        if cipher.enc.is_none() {
            cipher.init_encrypt();
            me.pos = 0;
            let n = cipher.iv.len();
            me.cap = n;
            me.buf[..n].copy_from_slice(&cipher.iv);
        }

        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if me.pos == me.cap && !me.read_done {
                let n = ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut me.buf))?;
                if n == 0 {
                    me.read_done = true;
                } else {
                    cipher.encrypt(&mut me.buf[..n]);

                    me.pos = 0;
                    me.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while me.pos < me.cap {
                let i = ready!(Pin::new(&mut *me.writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    me.pos += i;
                    me.amt += i as u64;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if me.pos == me.cap && me.read_done {
                ready!(Pin::new(&mut *me.writer).poll_flush(cx))?;
                return Poll::Ready(Ok(me.amt));
            }
        }
    }
}
