use shadowsocks::args::parse_args;
use shadowsocks::redir::Server;

fn main() {
    env_logger::init();
    let config = parse_args("redir").unwrap();
    log::info!(
        "config: \n{}",
        toml::ser::to_string_pretty(&config).unwrap()
    );

    let server = Server::new(config.redir.unwrap());
    awak::block_on(async {
        server.serve().await;
    })
}
