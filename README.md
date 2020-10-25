# shadowsocks-rs

[![Build](https://github.com/cssivision/shadowsocks-rs/workflows/build/badge.svg)](
https://github.com/cssivision/shadowsocks-rs/actions)
[![crate](https://img.shields.io/crates/v/shadowsocks-rs.svg)](https://crates.io/crates/shadowsocks-rs)
[![License](http://img.shields.io/badge/license-mit-blue.svg)](https://github.com/cssivision/shadowsocks-rs/blob/master/LICENSE)

minimalist port of shadowsocks, only reserve basic feature for personal usage.

# Installation
use cargo.
```sh
cargo install shadowsocks-rs
```
Fetch the [latest release](https://github.com/cssivision/shadowsocks-rs/releases).
# Configuration
config.json
```json
{
	"server_addr": "0.0.0.0:9006",
	"password": "password",
	"local_addr": "0.0.0.0:6009",
	"method": "aes-256-cfb",
	"timeout": 300,
	"keepalive_period": 600
}
```

# Usage 
#### server
```sh
RUST_LOG=info ssserver -c config.json
```

install a [client](https://shadowsocks.org/en/download/clients.html), connect to your server using your configuration, Done!

# Licenses

All source code is licensed under the [MIT License](https://github.com/cssivision/shadowsocks-rs/blob/master/LICENSE).
