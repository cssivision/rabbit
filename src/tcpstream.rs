use tokio_core::net;
use cipher::Cipher;
use std::io::{self, Read, Write};
use tokio_io::{AsyncRead, AsyncWrite};
use futures::{Async, Poll};
use bytes::{Buf, BufMut};

pub struct TcpStream {
    pub tcp_stream: net::TcpStream,
    pub cipher: Cipher,
}

impl TcpStream {
    pub fn new(c: Cipher, t: net::TcpStream) -> TcpStream {
        TcpStream {
            cipher: c,
            tcp_stream: t,
        }
    }

    fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Poll<usize, io::Error>
    where
        Self: Sized,
    {
        self.tcp_stream.read_buf(buf)
    }

    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error>
    where
        Self: Sized,
    {
        self.tcp_stream.write_buf(buf)
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp_stream.read(buf)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp_stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for TcpStream {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }

    fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        self.read_buf(buf)
    }
}

impl AsyncWrite for TcpStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.shutdown()
    }

    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        self.write_buf(buf)
    }
}
