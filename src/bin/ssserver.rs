extern crate futures;
extern crate serde_json;
extern crate shadowsocks_rs;
extern crate tokio_core;

use tokio_core::net::{TcpListener, TcpStream};
use futures::Future;
use shadowsocks_rs::config::Config;
use shadowsocks_rs::resolver::resolve;
use shadowsocks_rs::args::parse_args;

fn main() {
    if let Some(config) = parse_args() {
        println!("{}", serde_json::to_string_pretty(&config).unwrap());
        run(config);
    }
}

fn run(config: Config) {}
