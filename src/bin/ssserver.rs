extern crate shadowsocks_rs;

use shadowsocks_rs as shadowsocks;
use shadowsocks::config::Config;
use shadowsocks::resolver::resolve;

fn main() {
    println!("{:?}", Config::new(""));
}
