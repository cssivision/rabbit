use std::io;
use std::mem;
use std::net::IpAddr;
use std::sync::Arc;

use util::other;

use futures::{future, Future};
use tokio::runtime::current_thread::Runtime;
use trust_dns_resolver::ResolverFuture;

// This is an example of registering a static global resolver into any system.
//
// We may want to create a GlobalResolver as part of the Resolver library
//   in the mean time, this example has the necessary steps to do so.
//
// Thank you to @zonyitoo for the original example.

lazy_static! {
    // First we need to setup the global Resolver
    static ref GLOBAL_DNS_RESOLVER: ResolverFuture = {
        use std::sync::{Arc, Mutex, Condvar};
        use std::thread;

        // We'll be using this condvar to get the Resolver from the thread...
        let pair = Arc::new((Mutex::new(None::<ResolverFuture>), Condvar::new()));
        let pair2 = pair.clone();


        // Spawn the runtime to a new thread...
        //
        // This thread will manage the actual resolution runtime
        thread::spawn(move || {
            // A runtime for this new thread
            let mut runtime = Runtime::new().expect("failed to launch Runtime");

            // our platform independent future, result, see next blocks
            let future;

            // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
            #[cfg(any(unix, windows))]
            {
                // use the system resolver configuration
                future = ResolverFuture::from_system_conf().expect("Failed to create ResolverFuture");
            }

            // this will block the thread until the Resolver is constructed with the above configuration
            let resolver = runtime.block_on(future).expect("Failed to create DNS resolver");

            let &(ref lock, ref cvar) = &*pair2;
            let mut started = lock.lock().unwrap();
            *started = Some(resolver);
            cvar.notify_one();
            drop(started);

            runtime.run().expect("Resolver Thread shutdown!");
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

pub fn resolve(host: &str) -> Box<Future<Item = IpAddr, Error = io::Error> + Send> {
    let res = GLOBAL_DNS_RESOLVER
        .lookup_ip(host)
        .then(move |res| match res {
            Ok(r) => if let Some(addr) = r.iter().next() {
                future::ok(addr)
            } else {
                future::err(other("no ip return"))
            },
            Err(_) => future::err(other("resolve fail")),
        });

    Box::new(res)
}
