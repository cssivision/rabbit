use std::env;
use std::path::Path;
use std::{fs, io};

use serde_derive::{Deserialize, Serialize};

static LOCAL_ADDR: &str = "0.0.0.0:6009";
static SERVER_ADDR: &str = "0.0.0.0:9006";
static PASSWORD: &str = "password";
static METHOD: &str = "aes-256-cfb";

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(default)]
pub struct Config {
    pub local_addr: String,
    pub server_addr: String,
    pub password: String,
    pub method: String,
    pub unix_socket: bool,
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Config, io::Error> {
        if path.as_ref().exists() {
            let contents = fs::read_to_string(path)?;
            let config = match serde_json::from_str(&contents) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("{}", e);
                    return Err(io::Error::new(io::ErrorKind::Other, e));
                }
            };
            return Ok(config);
        }

        let mut config = Config {
            local_addr: LOCAL_ADDR.to_string(),
            server_addr: SERVER_ADDR.to_string(),
            password: PASSWORD.to_string(),
            method: METHOD.to_string(),
            unix_socket: false,
        };
        if let Ok(addr) = env::var("SHADOWSOCKS_LOCAL_ADDR") {
            config.local_addr = addr;
        }
        if let Ok(addr) = env::var("SHADOWSOCKS_SERVER_ADDR") {
            config.server_addr = addr;
        }
        if let Ok(pass) = env::var("SHADOWSOCKS_PASSWORD") {
            config.password = pass;
        }
        if let Ok(method) = env::var("SHADOWSOCKS_METHOD") {
            config.method = method;
        }
        if let Ok(unix_socket) = env::var("SHADOWSOCKS_UNIX_SOCKET") {
            config.method = unix_socket.parse().unwrap_or_default();
        }
        Ok(config)
    }
}
