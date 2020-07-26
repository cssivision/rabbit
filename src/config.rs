use std::env;
use std::path::Path;
use std::{fs, io};

use serde_derive::{Deserialize, Serialize};

static LOCAL_ADDR: &str = "0.0.0.0:6009";
static SERVER_ADDR: &str = "0.0.0.0:9006";
static PASSWORD: &str = "password";
static METHOD: &str = "aes-256-cfb";
static TIMEOUT: u64 = 100;
static KEEPALIVE_PEARID: u64 = 600;

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(default)]
pub struct Config {
    pub local_addr: String,
    pub server_addr: String,
    pub password: String,
    pub method: String,
    pub timeout: u64,
    pub keepalive_period: u64,
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
            Ok(config)
        } else {
            let mut config = Config {
                ..Default::default()
            };
            if config.local_addr.is_empty() {
                config.local_addr = if let Ok(addr) = env::var("SHADOWSOCKS_LOCAL_ADDR") {
                    addr
                } else {
                    LOCAL_ADDR.to_string()
                }
            }

            if config.server_addr.is_empty() {
                config.server_addr = if let Ok(addr) = env::var("SHADOWSOCKS_SERVER_ADDR") {
                    addr
                } else {
                    SERVER_ADDR.to_string()
                }
            }

            if config.password.is_empty() {
                config.password = if let Ok(addr) = env::var("SHADOWSOCKS_PASSWORD") {
                    addr
                } else {
                    PASSWORD.to_string()
                }
            }

            if config.method.is_empty() {
                config.method = if let Ok(addr) = env::var("SHADOWSOCKS_METHOD") {
                    addr
                } else {
                    METHOD.to_string()
                }
            }

            if config.timeout == 0 {
                config.timeout = if let Ok(timeout) = env::var("SHADOWSOCKS_TIMEOUT") {
                    timeout.parse().expect("invalid timeout value")
                } else {
                    TIMEOUT
                }
            }

            if config.keepalive_period == 0 {
                config.keepalive_period =
                    if let Ok(keepalive_period) = env::var("SHADOWSOCKS_KEEPALIVE_PERIOD") {
                        keepalive_period
                            .parse()
                            .expect("invalid keepalive_period value")
                    } else {
                        KEEPALIVE_PEARID
                    }
            }
            Ok(config)
        }
    }
}
