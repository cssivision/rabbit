use std::cell::OnceCell;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use dns_resolver::Resolver;
use rand::{thread_rng, Rng};

use crate::util::other;

const GLOBAL_RESOLVER: OnceCell<Resolver> = OnceCell::new();

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
