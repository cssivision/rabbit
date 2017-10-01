extern crate futures;
extern crate serde_json;
extern crate shadowsocks_rs;
extern crate tokio_core;
extern crate tokio_socks5;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::rc::Rc;
use std::cell::RefCell;

use shadowsocks_rs::config::Config;
use shadowsocks_rs::args::parse_args;
use shadowsocks_rs::cipher::Cipher;
use shadowsocks_rs::io::{write_all, DecryptReadCopy, EncryptWriteCopy};
use futures::{Future, Stream};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::Core;

static TYPE_IPV4: u8 = 1;
static TYPE_IPV6: u8 = 4;
static TYPE_DOMAIN: u8 = 3;

fn main() {
    if let Some(config) = parse_args() {
        println!("{}", serde_json::to_string_pretty(&config).unwrap());
        run(config);
    }
}

fn run(config: Config) {
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();
    let local_addr = config.local_addr.parse().expect("invalid local addr");
    let listener = TcpListener::bind(&local_addr, &handle).unwrap();
    let cipher = Cipher::new(&config.method, &config.password);

    println!("Listening connections on {}", local_addr);
    let streams = listener.incoming().and_then(|(socket, addr)| {
        println!("{}", addr);
        tokio_socks5::serve(socket)
    });

    let server = streams.for_each(move |(c1, host, port)| {
        println!("remote address: {}:{}", host, port);
        let rawaddr = generate_raw_addr(&host, port);
        let server_addr = config.server_addr.parse().expect("invalid server addr");
        let cipher = Rc::new(RefCell::new(cipher.reset()));
        let cipher_copy = cipher.clone();
        let pair = TcpStream::connect(&server_addr, &handle)
            .and_then(|c2| write_all(cipher_copy, c2, rawaddr).map(|c2| (c1, c2)));

        let pipe = pair.and_then(move |(c1, c2)| {
            let c1 = Rc::new(c1);
            let c2 = Rc::new(c2);

            let half1 = EncryptWriteCopy::new(c1.clone(), c2.clone(), cipher.clone());
            let half2 = DecryptReadCopy::new(c2, c1, cipher.clone());
            half1.join(half2)
        });

        let finish = pipe.map(|data| {
            println!("received {} bytes, responsed {} bytes", data.0, data.1)
        }).map_err(|e| println!("{}", e));

        handle.spawn(finish);
        Ok(())
    });

    lp.run(server).unwrap();
}

fn generate_raw_addr(host: &str, port: u16) -> Vec<u8> {
    if let Ok(host) = Ipv4Addr::from_str(host) {
        let mut rawaddr = vec![TYPE_IPV4];
        rawaddr.extend_from_slice(&host.octets());
        rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
        return rawaddr;
    }

    if let Ok(host) = Ipv6Addr::from_str(host) {
        let mut rawaddr = vec![TYPE_IPV6];
        rawaddr.extend_from_slice(&host.octets());
        rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
        return rawaddr;
    }

    let dm_len = host.as_bytes().len();
    let mut rawaddr = vec![TYPE_DOMAIN, dm_len as u8];
    rawaddr.extend_from_slice(host.as_bytes());
    rawaddr.extend_from_slice(&[((port >> 8) & 0xff) as u8, (port & 0xff) as u8]);
    return rawaddr;
}
