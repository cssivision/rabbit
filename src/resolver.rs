use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

use dns_resolver::Resolver;
use rand::{rng, Rng};

static GLOBAL_RESOLVER: OnceLock<Resolver> = OnceLock::new();

pub async fn resolve(host: &str) -> io::Result<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(host) {
        return Ok(addr);
    }
    let resolver = GLOBAL_RESOLVER.get_or_init(Resolver::new);
    let results = resolver.lookup_host(host).await?;
    if !results.is_empty() {
        let mut r = rng();
        let index = r.random_range(0..results.len());
        return Ok(results[index]);
    }
    Err(io::Error::other("resolve fail"))
}
