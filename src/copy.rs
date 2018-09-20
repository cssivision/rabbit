use std::io as std_io;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use futures::{Async, Future, Poll};
use tokio::net::TcpStream;
use tokio_io::{io, try_nb};

use crate::cipher::Cipher;
use crate::util::other;

/// A future representing reading all data from one side of a proxy connection
/// and decrypto data andthen writing it to another.
pub struct DecryptReadCopy {
    cipher: Arc<Mutex<Cipher>>,
    // The two I/O objects we'll be reading.
    reader: Arc<TcpStream>,
    writer: Arc<TcpStream>,
    buf: Vec<u8>,
    // The number of bytes we've written so far.
    amt: u64,
    pos: usize,
    cap: usize,
    read_done: bool,
}

pub fn decrypt_copy(
    reader: Arc<TcpStream>,
    writer: Arc<TcpStream>,
    cipher: Arc<Mutex<Cipher>>,
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

// Here we implement the `Future` trait for `DecryptReadCopy` directly.
// situations if needed.
impl Future for DecryptReadCopy {
    type Item = (u64, Arc<TcpStream>, Arc<TcpStream>);
    type Error = std_io::Error;

    fn poll(&mut self) -> Poll<(u64, Arc<TcpStream>, Arc<TcpStream>), std_io::Error> {
        let mut reader = &*self.reader;
        let mut writer = &*self.writer;
        let mut cipher = self.cipher.lock().unwrap();

        if cipher.dec.is_none() {
            if let Async::Ready(t) =
                try_nb!(io::read_exact(reader, vec![0u8; cipher.iv_len]).poll())
            {
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
                    let plain_data = match cipher.decrypt(&self.buf[..n]) {
                        Some(b) => b,
                        None => return Err(other("decrypt error")),
                    };

                    self.buf[..n].copy_from_slice(&plain_data[..n]);
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
                return Ok((self.amt, self.reader.clone(), self.writer.clone()).into());
            }
        }
    }
}

/// A future representing reading all data from one side of a proxy connection
/// and crypto data andthen writing it to another.
pub struct EncryptWriteCopy {
    cipher: Arc<Mutex<Cipher>>,
    // The two I/O objects we'll be reading.
    reader: Arc<TcpStream>,
    writer: Arc<TcpStream>,
    buf: Vec<u8>,
    // The number of bytes we've written so far.
    amt: u64,
    pos: usize,
    cap: usize,
    read_done: bool,
}

pub fn encrypt_copy(
    reader: Arc<TcpStream>,
    writer: Arc<TcpStream>,
    cipher: Arc<Mutex<Cipher>>,
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

// Here we implement the `Future` trait for `EncryptWriteCopy` directly.
impl Future for EncryptWriteCopy {
    type Item = (u64, Arc<TcpStream>, Arc<TcpStream>);
    type Error = std_io::Error;

    fn poll(&mut self) -> Poll<(u64, Arc<TcpStream>, Arc<TcpStream>), std_io::Error> {
        let mut reader = &*self.reader;
        let mut writer = &*self.writer;
        let mut cipher = self.cipher.lock().unwrap();

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
                    let cipher_data = match cipher.encrypt(&self.buf[..n]) {
                        Some(b) => b,
                        None => return Err(other("encrypt error")),
                    };

                    self.buf[..n].copy_from_slice(&cipher_data[..n]);
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
                return Ok((self.amt, self.reader.clone(), self.writer.clone()).into());
            }
        }
    }
}
