use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use crate::util::other;

use c_ares_resolver::FutureResolver;
use once_cell::sync::Lazy;

static GLOBAL_RESOLVER: Lazy<FutureResolver> =
    Lazy::new(|| FutureResolver::new().expect("new FutureResolver error"));

pub async fn resolve(host: &str) -> io::Result<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(host) {
        return Ok(addr);
    }

    let results = GLOBAL_RESOLVER
        .query_a(host)
        .await
        .map_err(|e| other(&e.to_string()))?;

    if let Some(result) = results.iter().next() {
        return Ok(IpAddr::V4(result.ipv4()));
    }

    Err(other("resolve fail"))
}
