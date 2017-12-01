use std::net::IpAddr;
use std::io;
use std::rc::Rc;

use futures::{future, Future};
use trust_dns_resolver::ResolverFuture;

pub fn resolve(
    host: &str,
    resolver: Rc<ResolverFuture>,
) -> Box<Future<Item = IpAddr, Error = io::Error>> {
    let res = resolver.lookup_ip(&host).then(move |res| {
        match res {
            Ok(r) => if let Some(addr) = r.iter().next() {
                future::ok(addr)
            } else {
                future::err(other_err("no ip return"))
            },
            Err(_) => future::err(other_err("resolve fail")),
        }
    });

    Box::new(res)
}

fn other_err(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}
