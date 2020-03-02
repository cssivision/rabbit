use std::io;
use std::net::IpAddr;

use crate::util::other;

use trust_dns_resolver::TokioAsyncResolver;

// pub async fn resolve(host: &str) -> io::Result<IpAddr> {
//     let host = format!("{}:0", host);
//     let ip = tokio::task::spawn_blocking(move || match host[..].to_socket_addrs() {
//         Ok(it) => {
//             let mut it = it.filter(|x| match x.ip() {
//                 IpAddr::V4(_) => true,
//                 IpAddr::V6(_) => false,
//             });
//             if let Some(addr) = it.next() {
//                 Ok(addr.ip())
//             } else {
//                 Err(other("no ip return"))
//             }
//         }
//         Err(e) => Err(e),
//     })
//     .await?;
//     ip
// }

pub async fn resolve(resolver: TokioAsyncResolver, host: &str) -> io::Result<IpAddr> {
    match resolver.lookup_ip(host).await {
        Ok(r) => {
            if let Some(addr) = r.iter().next() {
                Ok(addr)
            } else {
                Err(other("no ip return"))
            }
        }
        Err(e) => Err(other(&format!("resolve fail: {:?}", e))),
    }
}
