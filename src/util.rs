use std::io;
use openssl::sha::sha256;

static SHA256_LENGTH: u32 = 32;

pub fn other(desc: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

pub fn generate_key(data: &[u8], key_len: usize) -> Vec<u8> {
    let count = (key_len as f32 / SHA256_LENGTH as f32).ceil() as u32;
    let mut key = Vec::from(&sha256(data)[..]);
    let mut start = 0;
    for _ in 1..count {
        start += SHA256_LENGTH;
        let mut d = Vec::from(&key[(start - SHA256_LENGTH) as usize..start as usize]);
        d.extend_from_slice(data);
        key.extend_from_slice(&d);
    }
    key.truncate(key_len);
    key
}
