use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub server: Option<Vec<Server>>,
    pub client: Option<Vec<Client>>,
    pub redir: Option<Vec<Redir>>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub enum Mode {
    #[default]
    Tcp,
    Udp,
    Both,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Server {
    pub local_addr: Addr,
    pub password: String,
    pub method: String,
    #[serde(default)]
    pub mode: Mode,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Client {
    pub local_addr: Addr,
    pub server_addr: SocketAddr,
    pub password: String,
    pub method: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Redir {
    pub local_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub password: String,
    pub method: String,
    #[serde(default)]
    pub mode: Mode,
    pub redir_addr: Option<SocketAddr>,
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
        toml::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}
