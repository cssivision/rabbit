use md5::compute;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use crate::socks5::v5::{TYPE_DOMAIN, TYPE_IPV4, TYPE_IPV6};

static MD5_LENGTH: u32 = 16;

pub fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

pub fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
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

pub fn generate_raw_addr(host: &str, port: u16) -> Vec<u8> {
    match IpAddr::from_str(host) {
        Ok(IpAddr::V4(host)) => {
            let mut rawaddr = vec![TYPE_IPV4];
            rawaddr.extend_from_slice(&host.octets());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
        Ok(IpAddr::V6(host)) => {
            let mut rawaddr = vec![TYPE_IPV6];
            rawaddr.extend_from_slice(&host.octets());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
        _ => {
            let dm_len = host.as_bytes().len();
            let mut rawaddr = vec![TYPE_DOMAIN, dm_len as u8];
            rawaddr.extend_from_slice(host.as_bytes());
            rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
            rawaddr
        }
    }
}
