use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use awak::io::{AsyncRead, AsyncWrite};

use crate::cipher::Cipher;
use crate::util::eof;

pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    cipher: Arc<Mutex<Cipher>>,
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
#[derive(Debug)]
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
                            ready!(self.encrypter.poll_encrypt(cx, self.a, self.b))?
                        }
                        Direction::Decrypt => {
                            ready!(self.decrypter.poll_decrypt(cx, self.b, self.a))?
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
    cipher: Arc<Mutex<Cipher>>,
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
    need_flush: bool,
    iv: Vec<u8>,
}

impl CopyBuffer {
    fn new(cipher: Arc<Mutex<Cipher>>) -> CopyBuffer {
        let iv_len = cipher.lock().unwrap().iv_len;
        CopyBuffer {
            cipher,
            read_done: false,
            amt: 0,
            pos: 0,
            cap: 0,
            buf: Box::new([0; 1024 * 2]),
            need_flush: false,
            iv: vec![0u8; iv_len],
        }
    }

    fn poll_decrypt<'a, R, W>(
        &mut self,
        cx: &mut Context,
        mut reader: &'a mut R,
        writer: &'a mut W,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        if self.cipher.lock().unwrap().dec.is_none() {
            let mut cipher = self.cipher.lock().unwrap();
            while self.pos < self.iv.len() {
                let n = ready!(Pin::new(&mut reader).poll_read(cx, &mut self.iv[self.pos..]))?;
                self.pos += n;
                if n == 0 {
                    return Err(eof()).into();
                }
            }
            self.pos = 0;
            cipher.iv = self.iv.clone();
            cipher.init_decrypt(&self.iv);
        }
        self.poll_copy(cx, reader, writer, Direction::Decrypt)
    }

    fn poll_encrypt<'a, R, W>(
        &mut self,
        cx: &mut Context,
        reader: &'a mut R,
        writer: &'a mut W,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        if self.cipher.lock().unwrap().enc.is_none() {
            let mut cipher = self.cipher.lock().unwrap();
            cipher.init_encrypt();
            self.pos = 0;
            let n = cipher.iv.len();
            self.cap = n;
            self.buf[..n].copy_from_slice(&cipher.iv);
        }
        self.poll_copy(cx, reader, writer, Direction::Encrypt)
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
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = match Pin::new(&mut reader).poll_read(cx, &mut self.buf) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Try flushing when the reader has no progress to avoid deadlock
                        // when the reader depends on buffered writer.
                        if self.need_flush {
                            ready!(Pin::new(&mut writer).poll_flush(cx))?;
                            self.need_flush = false;
                        }
                        return Poll::Pending;
                    }
                };
                if n == 0 {
                    self.read_done = true;
                } else {
                    let mut cipher = self.cipher.lock().unwrap();
                    match direction {
                        Direction::Decrypt => {
                            cipher.decrypt(&mut self.buf[..n]);
                        }
                        Direction::Encrypt => {
                            cipher.encrypt(&mut self.buf[..n]);
                        }
                    }
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let i =
                    ready!(Pin::new(&mut writer).poll_write(cx, &self.buf[self.pos..self.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                ready!(Pin::new(&mut writer).poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}
