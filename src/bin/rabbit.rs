use std::future::pending;

use rabbit::args::parse_args;
use rabbit::{local, redir, server};

fn main() {
    env_logger::init();

    let config = parse_args("rabbit").unwrap();
    log::info!(
        "config: \n{}",
        toml::ser::to_string_pretty(&config).unwrap()
    );

    awak::block_on(async {
        if let Some(c) = config.client {
            awak::spawn(local::Server::new(c).serve()).detach();
        }
        if let Some(c) = config.server {
            awak::spawn(server::Server::new(c).serve()).detach();
        }
        if let Some(c) = config.redir {
            awak::spawn(redir::Server::new(c).serve()).detach();
        }
        pending().await
    })
}
