extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate serde_json;
extern crate shadowsocks_rs as shadowsocks;
extern crate tokio;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shadowsocks::args::parse_args;
use shadowsocks::cipher::Cipher;
use shadowsocks::io::{decrypt_copy, encrypt_copy, write_all};
use shadowsocks::socks5::{
    self,
    v5::{TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN},
};

use futures::{Future, Stream};
use tokio::net::{TcpListener, TcpStream};

fn main() {
    env_logger::init();
    let config = parse_args().unwrap();
    println!("{}", serde_json::to_string_pretty(&config).unwrap());

    let local_addr = config.local_addr.parse().expect("invalid local addr");
    let listener = TcpListener::bind(&local_addr).unwrap();
    let cipher = Cipher::new(&config.method, &config.password);
    let server_addr = config.server_addr.parse().expect("invalid server addr");

    println!("Listening connections on {}", local_addr);
    let server = listener
        .incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(move |socket| {
            let cipher = Arc::new(Mutex::new(cipher.reset()));
            let cipher_copy = cipher.clone();

            let pair = socks5::serve(socket).and_then(move |(c1, host, port)| {
                println!("proxy to address: {}:{}", host, port);
                let rawaddr = generate_raw_addr(&host, port);
                TcpStream::connect(&server_addr)
                    .and_then(|c2| write_all(cipher_copy, c2, rawaddr).map(|(c2, _)| (c1, c2)))
            });

            let pipe = pair.and_then(move |(c1, c2)| {
                let _ = c1.set_keepalive(Some(Duration::new(600, 0)));
                let _ = c2.set_keepalive(Some(Duration::new(600, 0)));
                let c1 = Arc::new(c1);
                let c2 = Arc::new(c2);

                let half1 = encrypt_copy(c1.clone(), c2.clone(), cipher.clone());
                let half2 = decrypt_copy(c2, c1, cipher.clone());
                half1.join(half2)
            });

            let finish = pipe
                .map(|data| {
                    debug!(
                        "received {} bytes, responsed {} bytes",
                        (data.0).0,
                        (data.1).0
                    )
                }).map_err(|e| println!("error: {}", e));

            tokio::spawn(finish);
            Ok(())
        });

    tokio::run(server);
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
