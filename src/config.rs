use std::net::SocketAddr;
use std::path::Path;
use std::{fs, io};

use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub local_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub password: String,
    pub method: String,
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Config, io::Error> {
        let contents = fs::read_to_string(path)?;
        let config =
            toml::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        return Ok(config);
    }
}
