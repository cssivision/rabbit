use std::io as std_io;
use std::mem;
use std::sync::{Arc, Mutex};

use futures::{Future, Poll};
use tokio_io::AsyncRead;

use cipher::Cipher;
use util::other;

pub struct DecryptReadExact<A, T> {
    state: State<A, T>,
}

enum State<A, T> {
    Reading {
        cipher: Arc<Mutex<Cipher>>,
        reader: A,
        buf: T,
        pos: usize,
    },
    Empty,
}

pub fn read_exact<A, T>(cipher: Arc<Mutex<Cipher>>, reader: A, buf: T) -> DecryptReadExact<A, T>
where
    A: AsyncRead,
    T: AsMut<[u8]>,
{
    DecryptReadExact {
        state: State::Reading {
            reader: reader,
            buf: buf,
            pos: 0,
            cipher: cipher,
        },
    }
}

fn eof() -> std_io::Error {
    std_io::Error::new(std_io::ErrorKind::UnexpectedEof, "early eof")
}

impl<A, T> Future for DecryptReadExact<A, T>
where
    A: AsyncRead,
    T: AsMut<[u8]>,
{
    type Item = (A, T);
    type Error = std_io::Error;

    fn poll(&mut self) -> Poll<(A, T), std_io::Error> {
        match self.state {
            State::Reading {
                ref mut reader,
                ref mut buf,
                ref mut pos,
                ref cipher,
            } => {
                let mut cipher = cipher.lock().unwrap();
                let buf = buf.as_mut();
                if cipher.dec.is_none() {
                    let mut iv = vec![0u8; cipher.iv_len];
                    while *pos < iv.len() {
                        let n = try_nb!(reader.read(&mut iv[*pos..]));
                        *pos += n;
                        if n == 0 {
                            return Err(eof());
                        }
                    }

                    *pos = 0;
                    cipher.iv = iv.clone();
                    cipher.init_decrypt(&iv);
                };

                while *pos < buf.len() {
                    let n = try_nb!(reader.read(&mut buf[*pos..]));
                    *pos += n;
                    if n == 0 {
                        return Err(eof());
                    }
                }

                let plain_data = match cipher.decrypt(&buf[..buf.len()]) {
                    Some(b) => b,
                    None => return Err(other("decrypt error")),
                };

                let copy_len = buf.len();
                buf[..copy_len].copy_from_slice(&plain_data[..copy_len]);
            }
            State::Empty => panic!("poll a ReadExact after it's done"),
        }

        match mem::replace(&mut self.state, State::Empty) {
            State::Reading { reader, buf, .. } => Ok((reader, buf).into()),
            State::Empty => panic!(),
        }
    }
}
