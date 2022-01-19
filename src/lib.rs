macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

pub mod args;
pub mod cipher;
pub mod config;
mod copy;
pub mod io;
pub mod listener;
pub mod local;
mod read_exact;
pub mod resolver;
pub mod server;
pub mod socks5;
pub mod util;
mod write_all;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub fn pending() -> Pending {
    Pending
}

pub struct Pending;

impl Future for Pending {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
