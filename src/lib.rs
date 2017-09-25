#[macro_use]
extern crate serde_derive;
extern crate serde_json;

pub mod config;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
