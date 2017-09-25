extern crate futures;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate trust_dns_resolver;

pub mod config;
pub mod resolver;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
