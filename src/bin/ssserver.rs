extern crate shadowsocks_rs;

use shadowsocks_rs::config::Config;
use shadowsocks_rs::resolver::resolve;

fn main() {
    println!("{:?}", Config::new(""));
}
