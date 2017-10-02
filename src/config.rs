use std::path::Path;
use std::fs::File;
use std::io::{self, Read};
use std::env;

use serde_json;

static LOCAL_ADDR: &str = "0.0.0.0:6009";
static SERVER_ADDR: &str = "0.0.0.0:9006";
static PASSWORD: &str = "password";
static METHOD: &str = "aes-256-cfb";
static TIMEOUT: u64 = 5;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    pub local_addr: String,
    pub server_addr: String,
    pub password: String,
    pub method: String,
    pub timeout: u64,
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Config, io::Error> {
        let mut config = Config {
            ..Default::default()
        };

        if let Ok(mut file) = File::open(path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            config = match serde_json::from_str(&contents) {
                Ok(c) => c,
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::Other, e));
                }
            };
        }

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

        Ok(config)
    }
}
