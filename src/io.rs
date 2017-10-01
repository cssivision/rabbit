use std::io as std_io;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{Read, Write};

use tokio_io::io;
use futures::{future, Async, Future, Poll};
use tokio_core::net::TcpStream;

use util::other;
use cipher::Cipher;

pub struct DecryptReadExact {
    cipher: Rc<RefCell<Cipher>>,
    reader: Rc<TcpStream>,
    buf: Vec<u8>,
    pos: usize,
}

pub fn read_exact(
    cipher: Rc<RefCell<Cipher>>,
    reader: Rc<TcpStream>,
    buf: Vec<u8>,
) -> DecryptReadExact {
    DecryptReadExact {
        reader: reader,
        buf: buf,
        pos: 0,
        cipher: cipher,
    }
}

fn eof() -> std_io::Error {
    std_io::Error::new(std_io::ErrorKind::UnexpectedEof, "early eof")
}

impl Future for DecryptReadExact {
    type Item = (Rc<TcpStream>, Vec<u8>);
    type Error = std_io::Error;

    fn poll(&mut self) -> Poll<(Rc<TcpStream>, Vec<u8>), std_io::Error> {
        let mut cipher = self.cipher.borrow_mut();
        let mut reader = &*self.reader;

        if cipher.dec.is_none() {
            let mut iv = Vec::with_capacity(cipher.iv_len);
            unsafe {
                iv.set_len(cipher.iv_len);
            }
            if let Async::Ready(t) = try_nb!(io::read_exact(reader, iv).poll()) {
                cipher.iv = t.1.clone();
                cipher.init_decrypt(&t.1);
            }
        }

        while self.pos < self.buf.len() {
            let n = try_nb!(reader.read(&mut self.buf[self.pos..]));
            self.pos += n;
            if n == 0 {
                return Err(eof());
            }
        }

        let a = match cipher.decrypt(&self.buf[..self.buf.len()]) {
            Some(b) => b,
            None => return Err(other("decrypt error")),
        };
        for i in 0..self.buf.len() {
            self.buf[i] = a[i];
        }

        Ok(Async::Ready((self.reader.clone(), self.buf.clone())))
    }
}

pub fn write_all(
    cipher: Rc<RefCell<Cipher>>,
    a: TcpStream,
    buf: Vec<u8>,
) -> Box<Future<Item = TcpStream, Error = std_io::Error>> {
    let mut cipher = cipher.borrow_mut();
    let mut data = if cipher.enc.is_none() {
        cipher.init_encrypt();
        cipher.iv.clone()
    } else {
        vec![]
    };

    let cipher_buf = match cipher.encrypt(&buf) {
        Some(b) => Vec::from(&b[..buf.len()]),
        None => {
            println!("encrypt error");
            return Box::new(future::err(other("encrypt error!")));
        }
    };
    data.extend_from_slice(&cipher_buf);

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
        DecryptReadCopy {
            cipher: cipher,
            reader: reader,
            writer: writer,
            buf: vec![0; 2 * 1024],
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

        if cipher.dec.is_none() {
            let mut iv = Vec::with_capacity(cipher.iv_len);
            unsafe {
                iv.set_len(cipher.iv_len);
            }
            if let Async::Ready(t) = try_nb!(io::read_exact(reader, iv).poll()) {
                cipher.iv = t.1.clone();
                cipher.init_decrypt(&t.1);
            }
        }

        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(reader.read(&mut self.buf));
                if n == 0 {
                    self.read_done = true;
                } else {
                    let a = match cipher.decrypt(&self.buf[..n]) {
                        Some(b) => b,
                        None => return Err(other("decrypt error")),
                    };
                    for i in 0..n {
                        self.buf[i] = a[i];
                    }
                    // println!("{}", String::from_utf8_lossy(&self.buf[..n]));
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
        EncryptWriteCopy {
            cipher: cipher,
            reader: reader,
            writer: writer,
            buf: vec![0; 2 * 1024],
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

        if cipher.enc.is_none() {
            cipher.init_encrypt();
            self.pos = 0;
            self.cap = cipher.iv.len();
            for i in 0..self.cap {
                self.buf[i] = cipher.iv[i];
            }
        }

        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(reader.read(&mut self.buf));
                if n == 0 {
                    self.read_done = true;
                } else {
                    let a = match cipher.encrypt(&self.buf[..n]) {
                        Some(b) => b,
                        None => return Err(other("encrypt error")),
                    };

                    for i in 0..n {
                        self.buf[i] = a[i];
                    }

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
