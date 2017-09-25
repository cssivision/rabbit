extern crate futures;
extern crate getopts;
#[macro_use]
extern crate log;
extern crate looli;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_socks5;

use std::env;

use getopts::Options;
use looli::config::Config;
use futures::{future, Future, Stream};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::Core;
use tokio_io::io::copy;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("c", "", "configuration path", "config");
    opts.optflag("h", "help", "print this help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            print!("{}", opts.usage("Usage: sslocal -c PATH"));
            return;
        }
    };

    if matches.opt_present("h") {
        print!("{}", opts.usage("Usage: sslocal -c PATH"));
        return;
    }

    let path = matches.opt_str("c").unwrap_or_default();
    let config = match Config::new(path) {
        Ok(c) => c,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    run(config);
}

fn run(config: Config) {
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();
    let addr = config.local_addr.parse().expect("invalid local addr");
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening connections on {}", addr);
    let streams = listener.incoming().and_then(|(socket, addr)| {
        debug!("{}", addr);
        tokio_socks5::serve(socket)
    });

    let server = streams.for_each(move |(c1, host, port)| {
        println!("{}", addr);
        println!("remote address: {}:{}", host, port);

        Ok(())
    });

    lp.run(server).unwrap();
}
