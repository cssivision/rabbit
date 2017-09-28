use std::io as std_io;

use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io;
use futures::{future, Future};
use rand::{thread_rng, Rng};
use tokio_core::net::TcpStream;

use util::other;
use cipher::Cipher;

pub fn read_exact<A, T>(
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

pub fn write_all<T>(
    mut cipher: Cipher,
    a: TcpStream,
    buf: T,
) -> Box<Future<Item = TcpStream, Error = std_io::Error>>
where
    T: AsRef<[u8]>,
{
    if cipher.e_iv.is_empty() {
        let mut rng = thread_rng();
        cipher.e_iv = rng.gen_iter::<u8>()
            .take(cipher.iv_len)
            .collect::<Vec<u8>>();
    }

    let mut data = cipher.e_iv.clone();
    let buf = match cipher.encrypt(buf.as_ref()) {
        Ok(buf) => buf,
        Err(e) => {
            println!("encrypt error: {}", e);
            return Box::new(future::err(other("encrypt error!")));
        }
    };
    data.extend_from_slice(&buf);

    Box::new(io::write_all(a, data).and_then(|(c, _)| future::ok(c)))
}

pub fn copy<R, W>(
    cipher: Cipher,
    reader: R,
    writer: W,
) -> Box<Future<Item = (u64, R, W), Error = std_io::Error>>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    unimplemented!()
}
