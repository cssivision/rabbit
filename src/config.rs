use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::cipher::Method;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Option<Vec<Server>>,
    pub client: Option<Vec<Client>>,
    pub redir: Option<Vec<Redir>>,
}

/// Which relay a listener runs.
///
/// `Stream` covers every stream transport, not just TCP: a `local_addr` that is
/// a path is served by a Unix listener, and `Stream::Unix` carries it.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Stream transports: TCP streams and Unix domain streams.
    #[default]
    Stream,
    /// Packet transports: UDP datagrams.
    Packet,
    /// Both relays at once.
    Both,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub local_addr: Addr,
    pub password: String,
    pub method: Method,
    #[serde(default)]
    pub transport: Transport,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub local_addr: Addr,
    pub server_addr: SocketAddr,
    pub password: String,
    pub method: Method,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Redir {
    pub local_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub password: String,
    pub method: Method,
    #[serde(default)]
    pub transport: Transport,
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
        toml::from_str(&contents).map_err(io::Error::other)
    }
}
