use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use dns_resolver::Resolver;
use once_cell::sync::Lazy;

use crate::util::other;

static GLOBAL_RESOLVER: Lazy<Resolver> = Lazy::new(Resolver::new);

pub async fn resolve(host: &str) -> io::Result<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(host) {
        return Ok(addr);
    }

    let host = host.to_string();
    let results = GLOBAL_RESOLVER.lookup_host(host).await?;

    if !results.is_empty() {
        return Ok(results[0]);
    }
    Err(other("resolve fail"))
}
