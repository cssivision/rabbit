use std::path::Path;
use std::fs::File;
use std::io::{self, Read};
use std::env;

use serde_json;

static LOCAL_ADDR: &str = "0.0.0.0";
static LOCAL_PORT: u32 = 6009;
static SERVER_ADDR: &str = "0.0.0.0";
static SERVER_PORT: u32 = 9006;
static PASSWORD: &str = "password";
static METHOD: &str = "aes-256-cfb";
static TIMEOUT: u32 = 5;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    local_addr: String,
    local_port: u32,
    server_addr: String,
    server_port: u32,
    password: String,
    method: String,
    timeout: u32,
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
            config.local_addr = if let Ok(addr) = env::var("LOOLI_LOCAL_ADDR") {
                addr
            } else {
                LOCAL_ADDR.to_string()
            }
        }

        if config.local_port == 0 {
            config.local_port = if let Ok(port) = env::var("LOOLI_LOCAL_PORT") {
                port.parse().expect("invalid local_port value")
            } else {
                LOCAL_PORT
            }
        }

        if config.server_addr.is_empty() {
            config.server_addr = if let Ok(addr) = env::var("LOOLI_SERVER_ADDR") {
                addr
            } else {
                SERVER_ADDR.to_string()
            }
        }

        if config.server_port == 0 {
            config.server_port = if let Ok(port) = env::var("LOOLI_SERVER_PORT") {
                port.parse().expect("invalid server_port value")
            } else {
                SERVER_PORT
            }
        }

        if config.password.is_empty() {
            config.password = if let Ok(addr) = env::var("LOOLI_PASSWORD") {
                addr
            } else {
                PASSWORD.to_string()
            }
        }

        if config.method.is_empty() {
            config.method = if let Ok(addr) = env::var("LOOLI_METHOD") {
                addr
            } else {
                METHOD.to_string()
            }
        }

        if config.timeout == 0 {
            config.timeout = if let Ok(timeout) = env::var("LOOLI_TIMEOUT") {
                timeout.parse().expect("invalid timeout value")
            } else {
                TIMEOUT
            }
        }

        Ok(config)
    }
}
