extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate serde_json;
extern crate shadowsocks_rs as shadowsocks;
extern crate tokio;
extern crate tokio_timer;
extern crate trust_dns_resolver;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::str;
use std::sync::{Arc, Mutex};

use shadowsocks::args::parse_args;
use shadowsocks::cipher::Cipher;
use shadowsocks::io::{decrypt_copy, encrypt_copy, read_exact};
use shadowsocks::resolver::resolve;
use shadowsocks::socks5::v5::{TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN};
use shadowsocks::util::other;

use futures::{future, Future, Stream};
use tokio::net::{TcpListener, TcpStream};

fn main() {
    env_logger::init().unwrap();
    let config = parse_args().expect("invalid config");
    println!("{}", serde_json::to_string_pretty(&config).unwrap());
    let listener = TcpListener::bind(&config.server_addr.parse().unwrap()).expect("failed to bind");
    let cipher = Cipher::new(&config.method, &config.password);

    let server = listener
        .incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(move |socket| {
            let cipher = Arc::new(Mutex::new(cipher.reset()));
            let address_info = get_addr_info(cipher.clone(), socket).map(move |(c, host, port)| {
                println!("proxy to address: {}:{}", host, port);
                (c, host, port)
            });

            let look_up = address_info
                .and_then(move |(c, host, port)| resolve(&host).map(move |addr| (c, addr, port)));

            let pair = look_up.and_then(move |(c1, addr, port)| {
                debug!("resolver addr to ip: {}", addr);
                TcpStream::connect(&SocketAddr::new(addr, port)).map(|c2| (c1, c2))
            });

            let pipe = pair.and_then(move |(c1, c2)| {
                let c1 = Arc::new(c1);
                let c2 = Arc::new(c2);

                let half1 = encrypt_copy(c2.clone(), c1.clone(), cipher.clone());
                let half2 = decrypt_copy(c1, c2, cipher.clone());
                half1.join(half2)
            });

            let close = pipe.and_then(move |((n1, c1, c2), (n2, _, _))| {
                c1.shutdown(Shutdown::Both)
                    .and(c2.shutdown(Shutdown::Both))
                    .map(|_| (n1, n2))
            });

            let finish = close
                .map(|data| debug!("received {} bytes, responsed {} bytes", data.0, data.1))
                .map_err(|e| println!("error: {}", e));

            tokio::spawn(finish);
            Ok(())
        });

    tokio::run(server);
}

fn get_addr_info(
    cipher: Arc<Mutex<Cipher>>,
    conn: TcpStream,
) -> impl Future<Item = (TcpStream, String, u16), Error = io::Error> + Send {
    let address_type = read_exact(cipher.clone(), conn, vec![0u8; 1]);

    address_type.and_then(move |(c, buf)| {
        match buf[0] {
            // For IPv4 addresses, we read the 4 bytes for the address as
            // well as 2 bytes for the port.
            TYPE_IPV4 => mybox(read_exact(cipher.clone(), c, vec![0u8; 6]).map(|(c, buf)| {
                let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                (c, format!("{}", addr), port)
            })),

            // For IPv6 addresses there's 16 bytes of an address plus two
            // bytes for a port, so we read that off and then keep going.
            TYPE_IPV6 => mybox(
                read_exact(cipher.clone(), c, vec![0u8; 18]).map(|(conn, buf)| {
                    let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                    let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                    let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                    let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                    let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                    let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                    let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                    let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                    let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                    (conn, format!("{}", addr), port)
                }),
            ),

            // The SOCKSv5 protocol not only supports proxying to specific
            // IP addresses, but also arbitrary hostnames.
            TYPE_DOMAIN => mybox(
                read_exact(cipher.clone(), c, vec![0u8])
                    .and_then(move |(conn, buf)| {
                        read_exact(cipher.clone(), conn, vec![0u8; buf[0] as usize + 2])
                    }).and_then(|(conn, buf)| {
                        let hostname = &buf[..buf.len() - 2];
                        let hostname = if let Ok(hostname) = str::from_utf8(hostname) {
                            hostname
                        } else {
                            return future::err(other("hostname include invalid utf8"));
                        };

                        let pos = buf.len() - 2;
                        let port = ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16);
                        future::ok((conn, hostname.to_string(), port))
                    }),
            ),
            n => {
                error!("unknown address type, received: {}", n);
                mybox(future::err(other("unknown address type, received")))
            }
        }
    })
}

fn mybox<F: Future + 'static + Send>(f: F) -> Box<Future<Item = F::Item, Error = F::Error> + Send> {
    Box::new(f)
}
