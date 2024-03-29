use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

use dns_resolver::Resolver;
use rand::{thread_rng, Rng};

use crate::util::other;

static GLOBAL_RESOLVER: OnceLock<Resolver> = OnceLock::new();

pub async fn resolve(host: &str) -> io::Result<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(host) {
        return Ok(addr);
    }
    let host = host.to_string();

    let results = GLOBAL_RESOLVER
        .get_or_init(Resolver::new)
        .lookup_host(host)
        .await?;
    if !results.is_empty() {
        return Ok(results[thread_rng().gen_range(0..results.len())]);
    }
    Err(other("resolve fail"))
}
