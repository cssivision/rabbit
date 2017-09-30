use std::io;
use md5::compute;

static MD5_LENGTH: u32 = 16;

pub fn other(desc: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

pub fn generate_key(data: &[u8], key_len: usize) -> Vec<u8> {
    let count = (key_len as f32 / MD5_LENGTH as f32).ceil() as u32;
    let mut key = Vec::from(&compute(data)[..]);
    let mut start = 0;
    for _ in 1..count {
        start += MD5_LENGTH;
        let mut d = Vec::from(&key[(start - MD5_LENGTH) as usize..start as usize]);
        d.extend_from_slice(data);
        let d = compute(d);
        key.extend_from_slice(&*d);
    }
    key
}
