use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::str::FromStr;

use dns_resolver::Resolver;
use rand::{thread_rng, Rng};

use crate::util::other;

thread_local! {
    static GLOBAL_RESOLVER: Rc<Resolver> = Rc::new(Resolver::new());
}

pub async fn resolve(host: &str) -> io::Result<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(host) {
        return Ok(addr);
    }
    let host = host.to_string();

    let resolver = GLOBAL_RESOLVER.with(|r| r.clone());
    let results = resolver.lookup_host(host).await?;
    if !results.is_empty() {
        return Ok(results[thread_rng().gen_range(0..results.len())]);
    }
    Err(other("resolve fail"))
}
