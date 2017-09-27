use std::io;

use tokio_io::{AsyncRead, AsyncWrite};
use futures::Future;
use tokio_core::net::TcpStream;
use cipher;

pub fn read_exact<A, T>(a: A, buf: T) -> Box<Future<Item = (A, T), Error = io::Error>>
where
    A: AsyncRead,
    T: AsMut<[u8]>,
{
    unimplemented!()
}

pub fn write_all<A, T>(a: A, buf: T) -> Box<Future<Item = (A, T), Error = io::Error>>
where
    A: AsyncWrite,
    T: AsRef<[u8]>,
{
    unimplemented!()
}

pub fn copy<R, W>(reader: R, writer: W) -> Box<Future<Item = (u64, R, W), Error = io::Error>>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    unimplemented!()
}
