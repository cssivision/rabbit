use std::io;
use std::net::IpAddr;

use crate::util::other;

use c_ares_resolver::FutureResolver;
use once_cell::sync::Lazy;

static GLOBAL_RESOLVER: Lazy<FutureResolver> =
    Lazy::new(|| c_ares_resolver::FutureResolver::new().unwrap());

pub async fn resolve(host: &str) -> io::Result<IpAddr> {
    let results = GLOBAL_RESOLVER
        .query_a(host)
        .await
        .map_err(|e| other(&e.to_string()))?;

    if let Some(result) = results.iter().next() {
        return result
            .to_string()
            .parse::<IpAddr>()
            .map_err(|e| other(&e.to_string()));
    }

    Err(other("resolve fail"))
}
