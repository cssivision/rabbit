use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{fs, io};

use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub server: Vec<Server>,
    pub client: Vec<Client>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Server {
    pub local_addr: Addr,
    pub password: String,
    pub method: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Client {
    pub local_addr: Addr,
    pub server_addr: SocketAddr,
    pub password: String,
    pub method: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Addr {
    Socket(SocketAddr),
    Path(PathBuf),
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Config> {
        let contents = fs::read_to_string(path)?;
        let config: Config =
            toml::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        return Ok(config);
    }
}
