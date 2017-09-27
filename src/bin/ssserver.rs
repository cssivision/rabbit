extern crate serde_json;
extern crate shadowsocks_rs;

use shadowsocks_rs::config::Config;
use shadowsocks_rs::resolver::resolve;
use shadowsocks_rs::args::parse_args;

fn main() {
    if let Some(config) = parse_args() {
        println!("{}", serde_json::to_string_pretty(&config).unwrap());
    }
}
