use std::net::IpAddr;
use std::io;
use std::rc::Rc;

use futures::{future, Future};
use trust_dns_resolver::ResolverFuture;

use util::other;

pub fn resolve(
    host: &str,
    resolver: Rc<ResolverFuture>,
) -> Box<Future<Item = IpAddr, Error = io::Error>> {
    let res = resolver.lookup_ip(&host).then(move |res| {
        match res {
            Ok(r) => if let Some(addr) = r.iter().next() {
                future::ok(addr)
            } else {
                future::err(other("no ip return"))
            },
            Err(_) => future::err(other("resolve fail")),
        }
    });

    Box::new(res)
}
