//! Bulk copy between the two halves of a proxied connection.
//!
//! This mirrors `awak::util::copy_bidirectional` but with a much larger buffer.
//! `awak`'s helper reads in 2 KiB chunks, so every relay record is 2 KiB: each
//! one costs an AEAD call, a length header and an allocation. Copying 32 KiB at
//! a time lets the cipher emit a few full-size records per syscall instead.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use futures_util::io::{AsyncRead, AsyncWrite};

const COPY_BUFFER_SIZE: usize = 64 * 1024;

struct CopyBuffer {
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
    need_flush: bool,
}

impl CopyBuffer {
    fn new() -> CopyBuffer {
        CopyBuffer {
            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: Box::new([0; COPY_BUFFER_SIZE]),
            need_flush: false,
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: &mut R,
        mut writer: &mut W,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            if self.pos == self.cap && !self.read_done {
                let n = match Pin::new(&mut reader).poll_read(cx, &mut self.buf) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
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
                    self.pos = 0;
                    self.cap = n;
                }
            }

            while self.pos < self.cap {
                let i =
                    ready!(Pin::new(&mut writer).poll_write(cx, &self.buf[self.pos..self.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                }
                self.pos += i;
                self.amt += i as u64;
                self.need_flush = true;
            }

            if self.pos == self.cap && self.read_done {
                ready!(Pin::new(&mut writer).poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

enum TransferState {
    Running(CopyBuffer),
    Close(u64),
    Done(u64),
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    r: &mut A,
    mut w: &mut B,
) -> Poll<io::Result<u64>>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    loop {
        match state {
            TransferState::Running(buf) => {
                let count = ready!(buf.poll_copy(cx, r, w))?;
                *state = TransferState::Close(count);
            }
            TransferState::Close(count) => {
                ready!(Pin::new(&mut w).poll_close(cx))?;
                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
        } = &mut *self;

        let a_to_b = transfer_one_direction(cx, a_to_b, &mut *a, &mut *b)?;
        let b_to_a = transfer_one_direction(cx, b_to_a, &mut *b, &mut *a)?;

        let a_to_b = ready!(a_to_b);
        let b_to_a = ready!(b_to_a);

        Poll::Ready(Ok((a_to_b, b_to_a)))
    }
}

pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running(CopyBuffer::new()),
        b_to_a: TransferState::Running(CopyBuffer::new()),
    }
    .await
}
