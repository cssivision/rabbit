use std::io;
use std::mem;
use std::net::IpAddr;

use util::other;

use futures::{future, Future};
use tokio::runtime::current_thread::Runtime;
use trust_dns_resolver::AsyncResolver;

lazy_static! {
    // First we need to setup the global Resolver
    static ref GLOBAL_DNS_RESOLVER: AsyncResolver = {
        use std::sync::{Arc, Mutex, Condvar};
        use std::thread;

        // We'll be using this condvar to get the Resolver from the thread...
        let pair = Arc::new((Mutex::new(None::<AsyncResolver>), Condvar::new()));
        let pair2 = pair.clone();

        // Spawn the runtime to a new thread...
        //
        // This thread will manage the actual resolution runtime
        thread::spawn(move || {
            // A runtime for this new thread
            let mut runtime = Runtime::new().expect("failed to launch Runtime");
            let (resolver, bg) = AsyncResolver::from_system_conf().expect("Failed to create ResolverFuture");

            let &(ref lock, ref cvar) = &*pair2;
            let mut started = lock.lock().unwrap();
            *started = Some(resolver);
            cvar.notify_one();
            drop(started);

            runtime.block_on(bg).expect("Fail to create DNS resolver");
        });

        // Wait for the thread to start up.
        let &(ref lock, ref cvar) = &*pair;
        let mut resolver = lock.lock().unwrap();
        while resolver.is_none() {
            resolver = cvar.wait(resolver).unwrap();
        }

        // take the started resolver
        let resolver = mem::replace(&mut *resolver, None);

        // set the global resolver
        resolver.expect("resolver should not be none")
    };
}

pub fn resolve(host: &str) -> impl Future<Item = IpAddr, Error = io::Error> + Send {
    GLOBAL_DNS_RESOLVER.lookup_ip(host).then(|res| match res {
        Ok(r) => if let Some(addr) = r.iter().next() {
            future::ok(addr)
        } else {
            future::err(other("no ip return"))
        },
        Err(_) => future::err(other("resolve fail")),
    })
}
