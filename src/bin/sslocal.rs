extern crate futures;
#[macro_use]
extern crate log;
extern crate serde_json;
extern crate shadowsocks_rs;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_socks5;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use shadowsocks_rs::config::Config;
use shadowsocks_rs::args::parse_args;
use shadowsocks_rs::tcpstream;
use shadowsocks_rs::cipher::Cipher;
use futures::{Future, Stream};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::Core;
use tokio_io::io::write_all;

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

    println!("Listening connections on {}", local_addr);
    let streams = listener.incoming().and_then(|(socket, addr)| {
        debug!("{}", addr);
        tokio_socks5::serve(socket)
    });

    let server = streams.for_each(move |(c1, host, port)| {
        println!("remote address: {}:{}", host, port);
        let rawaddr = generate_raw_addr(&host, port);
        let server_addr = config.server_addr.parse().expect("invalid server addr");
        TcpStream::connect(&server_addr, &handle).and_then(|c2| {
            let cipher = Cipher::new(&config.method, &config.password);
            let c2 = tcpstream::TcpStream::new(cipher, c2);
            write_all(c2, rawaddr)
        });

        Ok(())
    });

    lp.run(server).unwrap();
}

fn generate_raw_addr(host: &str, port: u16) -> Vec<u8> {
    if Ipv4Addr::from_str(host).is_ok() {
        let mut rawaddr = vec![TYPE_IPV4];
        rawaddr.extend_from_slice(host.as_bytes());
        return rawaddr;
    }

    if Ipv6Addr::from_str(host).is_ok() {
        let mut rawaddr = vec![TYPE_IPV6];
        rawaddr.extend_from_slice(host.as_bytes());
        return rawaddr;
    }

    let mut rawaddr = vec![TYPE_DOMAIN, ((port >> 8) & 0xff) as u8, (port & 0xff) as u8];
    rawaddr.extend_from_slice(host.as_bytes());
    return rawaddr;
}
