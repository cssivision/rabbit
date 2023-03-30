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
            local::Server::new(c).serve();
        }
        if let Some(c) = config.server {
            server::Server::new(c).serve();
        }
        if let Some(c) = config.redir {
            redir::Server::new(c).serve();
        }
        pending().await
    })
}
