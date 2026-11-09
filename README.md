# rabbit

[![Build](https://github.com/cssivision/rabbit/workflows/build/badge.svg)](
https://github.com/cssivision/rabbit/actions)
[![License](http://img.shields.io/badge/license-mit-blue.svg)](https://github.com/cssivision/rabbit/blob/master/LICENSE)

personal tunnel in rust.

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

## UDP

A `transport = "packet"` entry relays UDP datagrams instead of streams:

```toml
[[server]]
local_addr = "127.0.0.1:19030"
password = "AAAAAAAAAAAAAAAAAAAAAA=="
method = "2022-blake3-aes-128-gcm"
transport = "packet"
```

Clients are configured with `[[client]]` (socks5 mode) sections; on Linux a
`[[redir]]` section adds transparent proxying. `transport` accepts `"stream"`
(TCP streams and Unix domain sockets), `"packet"` (UDP datagrams) or `"both"`;
it defaults to `"stream"`.

The UDP wire format follows the shadowsocks specification and is **not
compatible with rabbit versions before the 2022 UDP work**:

* legacy AEAD / stream ciphers: `salt | SOCKS5 address | payload | tag`, a fresh
  salt per datagram in both directions (SIP004).
* `2022-*` ciphers: SIP022, i.e. an encrypted separate header carrying the
  session id and packet id, a per-session subkey and a replay window
  (`2022-blake3-chacha20-poly1305` puts the nonce in front instead).

The server side has been tested against other shadowsocks implementations for
all three 2022 methods over UDP.

# Supported ciphers

| Family | Methods |
| --- | --- |
| AEAD 2022 (SIP022) | `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` |
| AEAD (SIP004) | `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-poly1305`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305` |
| Stream | `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `camellia-128-cfb`, `camellia-192-cfb`, `camellia-256-cfb`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `chacha20`, `chacha20-ietf`, `salsa20` |

`2022-*` methods take the base64 encoded pre-shared key as the `password`
(16 bytes for `aes-128-gcm`, 32 bytes otherwise), and are supported for both
TCP and UDP.

# Usage

`rabbit` is a single binary: it starts every component present in the config
file and runs until interrupted.

```sh
RUST_LOG=info ./rabbit -c config.toml
```

# Licenses

All source code is licensed under the [MIT License](https://github.com/cssivision/rabbit/blob/master/LICENSE).
