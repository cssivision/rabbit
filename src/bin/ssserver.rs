use std::sync::{Arc, Mutex};
use std::net::{Ipv6Addr, Ipv4Addr};
use std::io::Error;
use std::str;

use shadowsocks_rs as shadowsocks;
use shadowsocks::args::parse_args;
use shadowsocks::cipher::Cipher;
use shadowsocks::io::read_exact;
// use shadowsocks::io::{decrypt_copy, encrypt_copy, read_exact};
// use shadowsocks::resolver::resolve;
use shadowsocks::socks5::v5::{TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN};
use shadowsocks::util::other;

use tokio::net::{TcpListener, TcpStream};
use log::{debug, error};
use futures::FutureExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let config = parse_args("ssserver").expect("invalid config");
    println!("{}", serde_json::to_string_pretty(&config).unwrap());
    let cipher = Cipher::new(&config.method, &config.password);
    let mut listener = TcpListener::bind(config.server_addr).await?;

    loop {
        let (socket, _) = listener.accept().await?;
        let cipher = Arc::new(Mutex::new(cipher.reset()));

        let proxy = proxy(cipher, socket).map(|r| {
            if let Err(e) = r {
                error!("Failed to proxy; error={}", e);
            }
        });

        tokio::spawn(proxy);
    }
}

async fn proxy(cipher: Arc<Mutex<Cipher>>, mut socket: TcpStream) -> Result<(), Error> {
    let (host, port) = get_addr_info(cipher.clone(), &mut socket).await?;
    
    Ok(())
}

// fn main() {
//     env_logger::init();
//     let config = parse_args("ssserver").expect("invalid config");
//     println!("{}", serde_json::to_string_pretty(&config).unwrap());
//     let listener = TcpListener::bind(&config.server_addr.parse().unwrap()).expect("failed to bind");
//     let cipher = Cipher::new(&config.method, &config.password);

//     let server = listener
//         .incoming()
//         .map_err(|e| eprintln!("accept failed = {:?}", e))
//         .for_each(move |socket| {
//             let cipher = Arc::new(Mutex::new(cipher.reset()));
//             let address_info = get_addr_info(cipher.clone(), socket).map(move |(c, host, port)| {
//                 println!("proxy to address: {}:{}", host, port);
//                 (c, host, port)
//             });

//             let look_up = address_info
//                 .and_then(move |(c, host, port)| resolve(&host).map(move |addr| (c, addr, port)));

//             let pair = look_up.and_then(move |(c1, addr, port)| {
//                 debug!("resolver addr to ip: {}", addr);
//                 TcpStream::connect(&SocketAddr::new(addr, port)).map(|c2| (c1, c2))
//             });

//             let keepalive_period = config.keepalive_period;
//             let pipe = pair.and_then(move |(c1, c2)| {
//                 let _ = c1.set_keepalive(Some(Duration::new(keepalive_period, 0)));
//                 let _ = c2.set_keepalive(Some(Duration::new(keepalive_period, 0)));
//                 let c1 = Arc::new(c1);
//                 let c2 = Arc::new(c2);

//                 let half1 = encrypt_copy(c2.clone(), c1.clone(), cipher.clone());
//                 let half2 = decrypt_copy(c1, c2, cipher.clone());
//                 half1.join(half2)
//             });

//             let finish = pipe
//                 .map(|data| {
//                     debug!(
//                         "received {} bytes, responsed {} bytes",
//                         (data.0).0,
//                         (data.1).0
//                     )
//                 }).map_err(|e| println!("error: {}", e));

//             tokio::spawn(finish);
//             Ok(())
//         });

//     tokio::run(server);
// }

async fn get_addr_info(cipher: Arc<Mutex<Cipher>>, conn: &mut TcpStream) -> Result<(String, usize), Error> {
    let t = &mut vec![0u8; 1];
    let _ = read_exact(cipher.clone(), conn, t).await?;

    match t[0] {
        // For IPv4 addresses, we read the 4 bytes for the address as
        // well as 2 bytes for the port.
        TYPE_IPV4 => {
            let buf = &mut vec![0u8; 6];
            let _ = read_exact(cipher.clone(), conn, buf).await?;
            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
            return Ok((format!("{}", addr), port as usize));
        },
        // For IPv6 addresses there's 16 bytes of an address plus two
        // bytes for a port, so we read that off and then keep going.
        TYPE_IPV6 => {
            let buf = &mut vec![0u8; 18];

            let _ = read_exact(cipher.clone(), conn, buf).await?;

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
            return Ok((format!("{}", addr), port as usize));
        },
        // The SOCKSv5 protocol not only supports proxying to specific
        // IP addresses, but also arbitrary hostnames.
        TYPE_DOMAIN => {
            let buf1 = &mut vec![0u8];
            let _ = read_exact(cipher.clone(), conn, buf1).await?;
            let buf2 = &mut vec![0u8; buf1[0] as usize + 2];
            let _ = read_exact(cipher.clone(), conn, buf2).await?;

            let hostname = &buf2[..buf2.len() - 2];
            let hostname = if let Ok(hostname) = str::from_utf8(hostname) {
                hostname
            } else {
                return Err(other("hostname include invalid utf8"));
            };

            let pos = buf2.len() - 2;
            let port = ((buf2[pos] as u16) << 8) | (buf2[pos + 1] as u16);
            return Ok((hostname.to_string(), port as usize));
        },
        n => {
            error!("unknown address type, received: {}", n);
            return Err(other("unknown address type, received"));
        }
    }
}
