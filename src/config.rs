#[macro_use]
use std::env;

#[derive(Serialize, Deserialize, Debug, Default)]
pub(crate) struct Config {}

impl Config {
    pub fn new() -> Config {
        Config {
            ..Default::default()
        }
    }
}
