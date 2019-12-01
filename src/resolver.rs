use std::io;
use std::net::SocketAddr;

use trust_dns_resolver::AsyncResolver;
use lazy_static::lazy_static;
use tokio;

lazy_static! {
    // setup the global Resolver
    static ref GLOBAL_DNS_RESOLVER: AsyncResolver = {
        let (resolver, bg) = AsyncResolver::from_system_conf().expect("Failed to create AsyncResolver");
        tokio::spawn(bg);
        resolver
    };
}

async fn resolve(host: &str) -> io::Result<SocketAddr> {
    match GLOBAL_DNS_RESOLVER.lookup_ip(host).await {
        Ok(r) => if let Some(addr) = r.iter().next() {
            Ok(addr)
        } else {
            Err(other("no ip return"))
        },
        Err(e) => Err(other(&format!("resolve fail: {:?}", e)))
    }
}
