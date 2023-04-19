use std::future::pending;
use std::thread;

use rabbit::args::parse_args;
use rabbit::{local, server};

fn main() {
    env_logger::init();

    let config = parse_args("rabbit").unwrap();
    log::info!(
        "config: \n{}",
        toml::ser::to_string_pretty(&config).unwrap()
    );

    let mut handles = Vec::new();
    let cpus = num_cpus::get();
    for _ in 0..cpus {
        let config = config.clone();
        let handle = thread::spawn(|| {
            slings::block_on(async {
                if let Some(c) = config.client {
                    local::Server::new(c).serve();
                }
                if let Some(c) = config.server {
                    server::Server::new(c).serve();
                }
                pending::<()>().await
            });
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }
}
