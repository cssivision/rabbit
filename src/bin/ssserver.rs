use shadowsocks::args::parse_args;
use shadowsocks::server::Server;

fn main() {
    env_logger::init();

    let config = parse_args("ssserver").expect("invalid config");
    log::info!("{}", toml::ser::to_string_pretty(&config).unwrap());

    let server = Server::new(config.server);
    awak::block_on(async {
        server.serve().await;
    })
}
