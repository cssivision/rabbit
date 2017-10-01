extern crate futures;
extern crate serde_json;
extern crate shadowsocks_rs;
extern crate tokio_core;

use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::Core;
use futures::{Future, Stream};
use shadowsocks_rs::config::Config;
use shadowsocks_rs::resolver::resolve;
use shadowsocks_rs::args::parse_args;
use shadowsocks_rs::io::{read_exact, DecryptReadCopy, EncryptWriteCopy};

fn main() {
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
    // let cipher = Cipher::new(&config.method, &config.password);

    // println!("Listening connections on {}", server_addr);
    // let streams = listener.incoming().and_then(|(socket, addr)| {
    //     let cipher = Rc::new(RefCell::new(cipher.reset()));
    //     let cipher_copy = cipher.clone();
    //     read_exact(cipher_copy, socket);
    //     println!("{}", addr);
    // });
}
