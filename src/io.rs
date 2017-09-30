use std::io as std_io;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{Read, Write};

use tokio_io::io;
use futures::{future, Future, Poll};
use rand::{thread_rng, Rng};
use tokio_core::net::TcpStream;

use util::other;
use cipher::Cipher;

pub fn read_exact(
    mut cipher: Cipher,
    a: TcpStream,
    buf: Vec<u8>,
) -> Box<Future<Item = (TcpStream, Vec<u8>), Error = std_io::Error>> {
    let iv_len = if cipher.d_iv.is_empty() {
        cipher.iv_len
    } else {
        0
    };

    Box::new(io::read_exact(a, Vec::with_capacity(iv_len)).and_then(
        move |(c, b)| {
            if !b.is_empty() {
                cipher.d_iv = b;
            }
            io::read_exact(c, Vec::with_capacity(buf.len())).and_then(move |(c, b)| {
                let buf = match cipher.decrypt(&b) {
                    Ok(b) => b,
                    Err(e) => {
                        println!("encrypt error: {}", e);
                        return future::err(other("encrypt error!"));
                    }
                };
                future::ok((c, buf))
            })
        },
    ))
}

pub fn write_all(
    cipher: Rc<RefCell<Cipher>>,
    a: TcpStream,
    buf: Vec<u8>,
) -> Box<Future<Item = TcpStream, Error = std_io::Error>> {
    let mut cipher = cipher.borrow_mut();
    if cipher.e_iv.is_empty() {
        let mut rng = thread_rng();
        cipher.e_iv = rng.gen_iter::<u8>()
            .take(cipher.iv_len)
            .collect::<Vec<u8>>();
    }

    let mut data = cipher.e_iv.clone();
    let buf = match cipher.encrypt(&buf) {
        Ok(buf) => buf,
        Err(e) => {
            println!("encrypt error: {}", e);
            return Box::new(future::err(other("encrypt error!")));
        }
    };
    data.extend_from_slice(&buf);

    Box::new(io::write_all(a, data).and_then(|(c, _)| future::ok(c)))
}

/// A future representing reading all data from one side of a proxy connection
/// and writing it to another.
///
/// This future, unlike the handshake performed above, is implemented via a
/// custom implementation of the `Future` trait rather than with combinators.
/// This is intended to show off how the combinators are not all that can be
/// done with futures, but rather more custom (or optimized) implementations can
/// be implemented with just a trait impl!
pub struct DecryptReadCopy {
    cipher: Rc<RefCell<Cipher>>,
    // The two I/O objects we'll be reading.
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,
    buf: Vec<u8>,
    // The number of bytes we've written so far.
    amt: u64,
    pos: usize,
    cap: usize,
    read_done: bool,
}

impl DecryptReadCopy {
    pub fn new(
        reader: Rc<TcpStream>,
        writer: Rc<TcpStream>,
        cipher: Rc<RefCell<Cipher>>,
    ) -> DecryptReadCopy {
        let buffer = vec![0; 2 * 1024];
        DecryptReadCopy {
            cipher: cipher,
            reader: reader,
            writer: writer,
            buf: buffer,
            read_done: false,
            amt: 0,
            cap: 0,
            pos: 0,
        }
    }
}

// Here we implement the `Future` trait for `Transfer` directly. This does not
// use any combinators, and shows how you might implement it in custom
// situations if needed.
impl Future for DecryptReadCopy {
    type Item = u64;
    type Error = std_io::Error;

    fn poll(&mut self) -> Poll<u64, std_io::Error> {
        let mut reader = &*self.reader;
        let mut writer = &*self.writer;
        let mut cipher = self.cipher.borrow_mut();

        if cipher.d_iv.is_empty() {
            try_nb!(io::read_exact(reader, &mut cipher.d_iv).poll());
        }
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(reader.read(&mut self.buf));
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.buf = match cipher.decrypt(&self.buf) {
                        Ok(b) => b,
                        Err(_) => return Err(other("decrypt error")),
                    };
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our self.buf has some data, let's write it out!
            while self.pos < self.cap {
                let i = try_nb!(writer.write(&self.buf[self.pos..self.cap]));
                if i == 0 {
                    return Err(std_io::Error::new(
                        std_io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    ));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                }
            }

            if self.pos == self.cap && self.read_done {
                try_nb!(writer.flush());
                return Ok(self.amt.into());
            }
        }
    }
}


pub struct EncryptWriteCopy {
    cipher: Rc<RefCell<Cipher>>,
    // The two I/O objects we'll be reading.
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,
    buf: Vec<u8>,
    // The number of bytes we've written so far.
    amt: u64,
    pos: usize,
    cap: usize,
    read_done: bool,
}

impl EncryptWriteCopy {
    pub fn new(
        reader: Rc<TcpStream>,
        writer: Rc<TcpStream>,
        cipher: Rc<RefCell<Cipher>>,
    ) -> EncryptWriteCopy {
        let buffer = vec![0; 2 * 1024];
        EncryptWriteCopy {
            cipher: cipher,
            reader: reader,
            writer: writer,
            buf: buffer,
            read_done: false,
            amt: 0,
            cap: 0,
            pos: 0,
        }
    }
}

// Here we implement the `Future` trait for `Transfer` directly. This does not
// use any combinators, and shows how you might implement it in custom
// situations if needed.
impl Future for EncryptWriteCopy {
    type Item = u64;
    type Error = std_io::Error;

    fn poll(&mut self) -> Poll<u64, std_io::Error> {
        let mut reader = &*self.reader;
        let mut writer = &*self.writer;
        let mut cipher = self.cipher.borrow_mut();

        if cipher.e_iv.is_empty() {
            let mut rng = thread_rng();
            cipher.e_iv = rng.gen_iter::<u8>()
                .take(cipher.iv_len)
                .collect::<Vec<u8>>();
        }

        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(reader.read(&mut self.buf));
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.buf = match cipher.encrypt(&self.buf) {
                        Ok(b) => b,
                        Err(_) => return Err(other("encrypt error")),
                    };
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our self.buf has some data, let's write it out!
            while self.pos < self.cap {
                let i = try_nb!(writer.write(&self.buf[self.pos..self.cap]));
                if i == 0 {
                    return Err(std_io::Error::new(
                        std_io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    ));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                }
            }

            if self.pos == self.cap && self.read_done {
                try_nb!(writer.flush());
                return Ok(self.amt.into());
            }
        }
    }
}
