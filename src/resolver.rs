use std::io;
use std::net::IpAddr;

use crate::util::other;

use c_ares_resolver::FutureResolver;
use lazy_static::lazy_static;

lazy_static! {
    static ref GLOBAL_RESOLVER: FutureResolver = c_ares_resolver::FutureResolver::new().unwrap();
}

pub async fn resolve(host: &str) -> io::Result<IpAddr> {
    let results = GLOBAL_RESOLVER
        .query_a(host)
        .await
        .map_err(|e| other(&e.to_string()))?;

    if let Some(result) = results.iter().next() {
        return result
            .to_string()
            .parse()
            .map_err(|e: std::net::AddrParseError| other(&e.to_string()));
    }

    Err(other("resolve fail"))
}
