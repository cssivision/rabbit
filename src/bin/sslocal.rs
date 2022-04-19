use shadowsocks::args::parse_args;
use shadowsocks::local::Server;

fn main() {
    env_logger::init();
    let config = parse_args("sslocal").unwrap();
    log::info!("{}", toml::ser::to_string_pretty(&config).unwrap());

    let server = Server::new(config.client);
    awak::block_on(async {
        server.serve().await;
    })
}
