use std::net::IpAddr;
use std::io;
use std::str::FromStr;
use std::rc::Rc;

use futures::{future, Future};
use trust_dns_resolver::ResolverFuture;

pub fn resolve(
    host: &str,
    resolver: Rc<ResolverFuture>,
) -> Box<Future<Item = IpAddr, Error = io::Error>> {
    if let Ok(addr) = IpAddr::from_str(&host) {
        return Box::new(future::ok(addr));
    }

    let look_up = resolver.lookup_ip(&host);
    let res = look_up.and_then(move |res| if let Some(addr) = res.iter().next() {
        future::ok(addr)
    } else {
        future::err(io::Error::new(
            io::ErrorKind::Other,
            "resolve fail".to_string(),
        ))
    });

    Box::new(res)
}
