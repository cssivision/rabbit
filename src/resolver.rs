use std::net::{ToSocketAddrs, IpAddr};
use std::io;

use crate::util::other;

use futures::executor::ThreadPool;
use lazy_static::lazy_static;
use futures::prelude::*;

lazy_static! {
    // setup the global Resolver
    static ref POOL: ThreadPool = ThreadPool::builder().create().unwrap();
}

pub async fn resolve(host: &str) -> io::Result<IpAddr> {
    let host = format!("{}:0", host);
    let (tx, rx) = futures::channel::oneshot::channel();

    POOL.spawn_obj_ok(
        async move {
            let _ = tx.send(match host[..].to_socket_addrs() {
                Ok(it) => {
                    let mut it = it.filter(|x| match x.ip() {
                        IpAddr::V4(_) => true,
                        _ => false,
                    });
                    if let Some(addr) = it.next() {
                        Ok(addr.ip())
                    } else {
                        Err(other("no ip return"))
                    }
                },
                Err(e) => Err(e),
            });
        }.boxed().into()
    );

    rx.await.unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Resolver future has been dropped",
        ))
    })
}

// use trust_dns_resolver::AsyncResolver;
// use lazy_static::lazy_static;
// use tokio;

// lazy_static! {
//     // setup the global Resolver
//     static ref GLOBAL_DNS_RESOLVER: AsyncResolver = {
//         let (resolver, bg) = AsyncResolver::from_system_conf().expect("Failed to create AsyncResolver");
//         tokio::spawn(bg);
//         resolver
//     };
// }

// async fn resolve(host: &str) -> io::Result<SocketAddr> {
//     match GLOBAL_DNS_RESOLVER.lookup_ip(host).await {
//         Ok(r) => if let Some(addr) = r.iter().next() {
//             Ok(addr)
//         } else {
//             Err(other("no ip return"))
//         },
//         Err(e) => Err(other(&format!("resolve fail: {:?}", e)))
//     }
// }
