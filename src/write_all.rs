use std::io as std_io;
use std::mem;
use std::sync::{Arc, Mutex};

// use futures::{Future, Poll};
// use tokio_io::{AsyncWrite, try_nb};
// use log::error;

// use crate::cipher::Cipher;
// use crate::util::other;

// pub struct EncryptWriteAll<A, T> {
//     state: State<A, T>,
// }

// enum State<A, T> {
//     Writing {
//         cipher: Arc<Mutex<Cipher>>,
//         a: A,
//         buf: T,
//         pos: usize,
//     },
//     Empty,
// }

// pub fn write_all<A, T>(cipher: Arc<Mutex<Cipher>>, a: A, buf: T) -> EncryptWriteAll<A, T>
// where
//     A: AsyncWrite,
//     T: AsMut<[u8]>,
// {
//     EncryptWriteAll {
//         state: State::Writing {
//             cipher: cipher,
//             a: a,
//             buf: buf,
//             pos: 0,
//         },
//     }
// }

// fn zero_write() -> std_io::Error {
//     std_io::Error::new(std_io::ErrorKind::WriteZero, "zero-length write")
// }

// impl<A, T> Future for EncryptWriteAll<A, T>
// where
//     A: AsyncWrite,
//     T: AsMut<[u8]>,
// {
//     type Item = (A, T);
//     type Error = std_io::Error;

//     fn poll(&mut self) -> Poll<(A, T), std_io::Error> {
//         match self.state {
//             State::Writing {
//                 ref mut a,
//                 ref mut buf,
//                 ref mut pos,
//                 ref cipher,
//             } => {
//                 let mut cipher = cipher.lock().unwrap();
//                 let buf = buf.as_mut();
//                 let mut data = if cipher.enc.is_none() {
//                     cipher.init_encrypt();
//                     cipher.iv.clone()
//                 } else {
//                     vec![]
//                 };

//                 let cipher_buf = match cipher.encrypt(&buf) {
//                     Some(b) => Vec::from(&b[..buf.len()]),
//                     None => {
//                         error!("encrypt error");
//                         return Err(other("encrypt error!"));
//                     }
//                 };
//                 data.extend_from_slice(&cipher_buf);
//                 while *pos < data.len() {
//                     let n = try_nb!(a.write(&data[*pos..]));
//                     *pos += n;
//                     if n == 0 {
//                         return Err(zero_write());
//                     }
//                 }
//             }
//             State::Empty => panic!("poll a WriteAll after it's done"),
//         }

//         match mem::replace(&mut self.state, State::Empty) {
//             State::Writing { a, buf, .. } => Ok((a, buf).into()),
//             State::Empty => panic!(),
//         }
//     }
// }
