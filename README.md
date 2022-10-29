# rabbit

[![Build](https://github.com/cssivision/rabbit/workflows/build/badge.svg)](
https://github.com/cssivision/rabbit/actions)
[![License](http://img.shields.io/badge/license-mit-blue.svg)](https://github.com/cssivision/rabbit/blob/master/LICENSE)

personal VPN in rust.

# Configuration
config.toml
```toml
[[server]]
local_addr = "127.0.0.1:9006"
password = "password"
method = "aes-128-cfb"

[[server]]
local_addr = "temp.sock"
password = "password"
method = "aes-128-cfb"
```

# Usage 
#### server
```sh
RUST_LOG=info ./rabbit -c config.toml
```

# Licenses

All source code is licensed under the [MIT License](https://github.com/cssivision/rabbit/blob/master/LICENSE).
