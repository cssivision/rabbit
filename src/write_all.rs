use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{ready, Context, Poll};

use futures_util::AsyncWrite;

use crate::cipher::Cipher;

enum State {
    Iv,
    Write(Vec<u8>),
    Done,
}

pub struct EncryptWriteAll<'a, W: ?Sized> {
    cipher: Rc<RefCell<Cipher>>,
    writer: &'a mut W,
    buf: &'a [u8],
    state: State,
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
        state: State::Iv,
    }
}

impl<W> Future for EncryptWriteAll<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        loop {
            match &mut me.state {
                State::Iv => {
                    let mut cipher = me.cipher.borrow_mut();
                    if cipher.enc.is_some() {
                        me.state = State::Write(vec![]);
                        continue;
                    }
                    cipher.init_encrypt();
                    let iv = cipher.iv.clone();
                    let iv_len = iv.len();
                    let mut data = iv;
                    data.extend_from_slice(me.buf);
                    cipher.encrypt(&mut data[iv_len..]);
                    me.state = State::Write(data);
                }
                State::Write(data) => {
                    while !data.is_empty() {
                        let n = ready!(Pin::new(&mut me.writer).poll_write(cx, data))?;
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        data.drain(0..n);
                    }
                    me.state = State::Done;
                }
                State::Done => {
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}
