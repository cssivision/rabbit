extern crate futures;
extern crate getopts;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_io;
extern crate trust_dns_resolver;

pub mod config;
pub mod resolver;
pub mod io;
pub mod util;
pub mod args;
mod cipher;
mod tcpstream;
