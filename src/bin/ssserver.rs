extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate num_cpus;
extern crate serde_json;
extern crate shadowsocks_rs;
extern crate tokio_core;
extern crate tokio_timer;
extern crate trust_dns_resolver;

use std::io;
use std::rc::Rc;
use std::cell::RefCell;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;
use std::time::Duration;

use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::Core;
use futures::{future, Future, Stream};
use trust_dns_resolver::ResolverFuture;
use tokio_timer::Timer;

use shadowsocks_rs::config::Config;
use shadowsocks_rs::resolver::resolve;
use shadowsocks_rs::cipher::Cipher;
use shadowsocks_rs::args::parse_args;
use shadowsocks_rs::util::other;
use shadowsocks_rs::io::{decrypt_copy, encrypt_copy, read_exact};

const TYPE_IPV4: u8 = 1;
const TYPE_IPV6: u8 = 4;
const TYPE_DOMAIN: u8 = 3;

fn main() {
    env_logger::init().unwrap();
    if let Some(config) = parse_args() {
        println!("{}", serde_json::to_string_pretty(&config).unwrap());
        run(config);
    }
}

fn run(config: Config) {
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();
    let server_addr = config.server_addr.parse().expect("invalid local addr");
    let listener = TcpListener::bind(&server_addr, &handle).unwrap();
    let resolver = Rc::new(ResolverFuture::from_system_conf(&handle).unwrap());
    let cipher = Cipher::new(&config.method, &config.password);
    let timer = Timer::default();

    println!("Listening connections on {}", server_addr);

    let server = listener.incoming().for_each(move |(socket, addr)| {
        debug!("remote address: {}", addr);
        let cipher = Rc::new(RefCell::new(cipher.reset()));
        let address_info =
            get_addr_info(cipher.clone(), Rc::new(socket)).map(move |(c, host, port)| {
                println!("proxy to address: {}:{}", host, port);
                (c, host, port)
            });

        let resolver = resolver.clone();
        let look_up = address_info.and_then(move |(c, host, port)| {
            resolve(&host, resolver).map(move |addr| (c, addr, port))
        });

        let handle_copy = handle.clone();
        let pair = look_up.and_then(move |(c1, addr, port)| {
            TcpStream::connect(&SocketAddr::new(addr, port), &handle_copy).map(|c2| (c1, c2))
        });

        let pipe = pair.and_then(move |(c1, c2)| {
            let c2 = Rc::new(c2);

            let half1 = encrypt_copy(c2.clone(), c1.clone(), cipher.clone());
            let half2 = decrypt_copy(c1, c2, cipher.clone());
            half1.join(half2)
        });

        let finish = pipe.map(|data| {
            debug!("received {} bytes, responsed {} bytes", data.0, data.1)
        }).map_err(|e| println!("error: {}", e));

        let timeout = timer.timeout(finish, Duration::new(config.timeout, 0));

        handle.spawn(timeout);
        Ok(())
    });

    lp.run(server).unwrap();
}

fn get_addr_info(
    cipher: Rc<RefCell<Cipher>>,
    conn: Rc<TcpStream>,
) -> Box<Future<Item = (Rc<TcpStream>, String, u16), Error = io::Error>> {
    let cipher_copy = cipher.clone();
    let address_type = read_exact(cipher_copy.clone(), conn, vec![0u8; 1]);
    let address = mybox(address_type.and_then(move |(c, buf)| {
        match buf[0] {
            // For IPv4 addresses, we read the 4 bytes for the address as
            // well as 2 bytes for the port.
            TYPE_IPV4 => mybox(read_exact(cipher.clone(), c, vec![0u8; 6]).and_then(
                |(c, buf)| {
                    let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                    let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    mybox(future::ok((c, format!("{}", addr), port)))
                },
            )),

            // For IPv6 addresses there's 16 bytes of an address plus two
            // bytes for a port, so we read that off and then keep going.
            TYPE_IPV6 => mybox(read_exact(cipher.clone(), c, vec![0u8; 18]).and_then(
                |(conn, buf)| {
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
                    mybox(future::ok((conn, format!("{}", addr), port)))
                },
            )),

            // The SOCKSv5 protocol not only supports proxying to specific
            // IP addresses, but also arbitrary hostnames.
            TYPE_DOMAIN => mybox(
                read_exact(cipher.clone(), c, vec![0u8])
                    .and_then(move |(conn, buf)| {
                        read_exact(cipher.clone(), conn, vec![0u8; buf[0] as usize + 2])
                    })
                    .and_then(|(conn, buf)| {
                        let hostname = &buf[..buf.len() - 2];
                        let hostname = if let Ok(hostname) = str::from_utf8(hostname) {
                            hostname
                        } else {
                            return mybox(future::err(other("hostname include invalid utf8")));
                        };

                        let pos = buf.len() - 2;
                        let port = ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16);
                        mybox(future::ok((conn, hostname.to_string(), port)))
                    }),
            ),
            n => {
                println!("unknown address type, received: {}", n);
                mybox(future::err(other("unknown address type, received")))
            }
        }
    }));
    address
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item = F::Item, Error = F::Error>> {
    Box::new(f)
}
