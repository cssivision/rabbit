use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use slings::{AsyncRead, AsyncWrite};

use crate::cipher::Cipher;
use crate::util::eof;

pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    cipher: Rc<RefCell<Cipher>>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running,
        b_to_a: TransferState::Running,
        decrypter: CopyBuffer::new(cipher.clone()),
        encrypter: CopyBuffer::new(cipher),
    }
    .await
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let a_to_b = self.transfer_one_direction(cx, Direction::Encrypt)?;
        let b_to_a = self.transfer_one_direction(cx, Direction::Decrypt)?;

        // It is not a problem if ready! returns early because transfer_one_direction for the
        // other direction will keep returning TransferState::Done(count) in future calls to poll
        let a_to_b = ready!(a_to_b);
        let b_to_a = ready!(b_to_a);

        Poll::Ready(Ok((a_to_b, b_to_a)))
    }
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
    decrypter: CopyBuffer,
    encrypter: CopyBuffer,
}

enum TransferState {
    Running,
    ShuttingDown(u64),
    Done(u64),
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

impl<'a, A, B> CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    fn transfer_one_direction(
        &mut self,
        cx: &mut Context<'_>,
        direction: Direction,
    ) -> Poll<io::Result<u64>> {
        let state = match direction {
            Direction::Encrypt => &mut self.a_to_b,
            Direction::Decrypt => &mut self.b_to_a,
        };
        loop {
            match state {
                TransferState::Running => {
                    let count = match direction {
                        Direction::Encrypt => {
                            ready!(self.encrypter.poll_encrypt(cx, self.a, self.b, direction))?
                        }
                        Direction::Decrypt => {
                            ready!(self.decrypter.poll_decrypt(cx, self.b, self.a, direction))?
                        }
                    };

                    *state = TransferState::ShuttingDown(count);
                }
                TransferState::ShuttingDown(count) => {
                    match direction {
                        Direction::Encrypt => ready!(Pin::new(&mut self.b).poll_close(cx))?,
                        Direction::Decrypt => ready!(Pin::new(&mut self.a).poll_close(cx))?,
                    };

                    *state = TransferState::Done(*count);
                }
                TransferState::Done(count) => return Poll::Ready(Ok(*count)),
            }
        }
    }
}

struct CopyBuffer {
    cipher: Rc<RefCell<Cipher>>,
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
    need_flush: bool,
}

impl CopyBuffer {
    fn new(cipher: Rc<RefCell<Cipher>>) -> CopyBuffer {
        CopyBuffer {
            cipher,
            read_done: false,
            amt: 0,
            pos: 0,
            cap: 0,
            buf: Box::new([0; 1024 * 2]),
            need_flush: false,
        }
    }

    fn poll_decrypt<'a, R, W>(
        &mut self,
        cx: &mut Context,
        mut reader: &'a mut R,
        writer: &'a mut W,
        direction: Direction,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        if self.cipher.borrow().dec.is_none() {
            let mut cipher = self.cipher.borrow_mut();
            let mut iv = vec![0u8; cipher.iv_len];
            while self.pos < iv.len() {
                let n = ready!(Pin::new(&mut reader).poll_read(cx, &mut iv[self.pos..]))?;
                self.pos += n;
                if n == 0 {
                    return Err(eof()).into();
                }
            }
            self.pos = 0;
            cipher.iv = iv.clone();
            cipher.init_decrypt(&iv);
        }
        self.poll_copy(cx, reader, writer, direction)
    }

    fn poll_encrypt<'a, R, W>(
        &mut self,
        cx: &mut Context,
        reader: &'a mut R,
        writer: &'a mut W,
        direction: Direction,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        if self.cipher.borrow().enc.is_none() {
            let mut cipher = self.cipher.borrow_mut();
            cipher.init_encrypt();
            self.pos = 0;
            let n = cipher.iv.len();
            self.cap = n;
            self.buf[..n].copy_from_slice(&cipher.iv);
        }
        self.poll_copy(cx, reader, writer, direction)
    }

    fn poll_copy<'a, R, W>(
        &mut self,
        cx: &mut Context,
        mut reader: &'a mut R,
        mut writer: &'a mut W,
        direction: Direction,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let me = &mut *self;
        let mut cipher = me.cipher.borrow_mut();
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if me.pos == me.cap && !me.read_done {
                let n = match Pin::new(&mut reader).poll_read(cx, &mut me.buf) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Try flushing when the reader has no progress to avoid deadlock
                        // when the reader depends on buffered writer.
                        if me.need_flush {
                            ready!(Pin::new(&mut writer).poll_flush(cx))?;
                            me.need_flush = false;
                        }
                        return Poll::Pending;
                    }
                };
                if n == 0 {
                    me.read_done = true;
                } else {
                    match direction {
                        Direction::Decrypt => {
                            cipher.decrypt(&mut me.buf[..n]);
                        }
                        Direction::Encrypt => {
                            cipher.encrypt(&mut me.buf[..n]);
                        }
                    }
                    me.pos = 0;
                    me.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while me.pos < me.cap {
                let i = ready!(Pin::new(&mut writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    me.pos += i;
                    me.amt += i as u64;
                    me.need_flush = true;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if me.pos == me.cap && me.read_done {
                ready!(Pin::new(&mut writer).poll_flush(cx))?;
                return Poll::Ready(Ok(me.amt));
            }
        }
    }
}
