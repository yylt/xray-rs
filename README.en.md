# xray-rs

Default language: English | [中文](./README.md)

A lightweight proxy core implemented in Rust, with composable inbound, outbound, routing, DNS, and transport capabilities.

## Features

- Inbounds: `http`, `socks`, `trojan`, `vless`, `reverse`
- Outbounds: `freedom`, `blackhole`, `socks`, `trojan`, `vless`, `reverse`
- Routing: supports `domain`, `ip`, `inboundTag`, and fallback
- Transport: supports `tcp`, `ws`, `grpc`, with optional `tls`
- DNS: built-in `DnsResolver` and standalone `rsdns` binary

## Quick Start

### Build

```bash
cargo build --release
```

Produces:

- `target/release/xray-rs`
- `target/release/rsdns`

### Run the main program

The default config format is **YAML**:

```bash
cargo run -- run -c config.yaml
# or
./target/release/xray-rs run -c config.yaml
```

The current default config filename for `run` is:

```bash
config.yaml
```

Also supported:

- `.yaml`
- `.yml`
- `.json`

## Minimal config example

```yaml
inbounds:
  - listen: 127.0.0.1
    port: 1080
    tag: socks-in
    protocol: socks

outbounds:
  - tag: direct
    protocol: freedom
  - tag: block
    protocol: blackhole

routing:
  domainStrategy: AsIs
  rules:
    - domain:
        - example.com
      outboundTag: direct
  fallback:
    tags:
      - direct

dns:
  disableCache: false
  hosts:
    - localhost:127.0.0.1
  servers:
    - 1.1.1.1:53
    - tcp://8.8.8.8:53
```

## Supported Platforms

Based on the current source code:

### OS

- **Linux**: recommended platform; includes `linux/android` zero-copy forwarding optimization paths
- **Android**: shares part of the forwarding optimization path with Linux
- **macOS / other Unix-like systems**: has Unix socket related support, but does not use Linux-specific optimization paths
- **Windows**: parts of the main program may build, but Unix sockets are unavailable; `tun` and some low-level behavior should be verified per target build

### Architectures

The source code does not show architecture-specific restrictions, so the practical expectation is:

- common `x86_64`
- common `aarch64`

Other architectures depend on dependency support, enabled features, and target platform compatibility.

### Platform notes

- `Unix domain socket` is only available under `#[cfg(unix)]`
- `StreamForwarder` has `libc::splice` optimization on `linux/android`
- `tun` support depends on the `tun` feature and target-platform support

## Documentation

- Usage Guide (Chinese): [`docs/usage.zh.md`](./docs/usage.zh.md)
- Usage Guide (English): [`docs/usage.en.md`](./docs/usage.en.md)
- Architecture (Chinese): [`docs/arch.zh.md`](./docs/arch.zh.md)
- Architecture (English): [`docs/arch.en.md`](./docs/arch.en.md)

## rsdns

The repository also includes a standalone DNS binary:

```bash
cargo run --bin rsdns -- -c rsdns.yaml
```

From the current source:

- default config file: `rsdns.yaml`
- supports `forward`, `block`, and `rewrite`
- listening is currently implemented mainly for `udp://`

## Development

```bash
cargo test
```

Common features:

- `tun`
- `mimalloc`
- `jemalloc`
- `aws-lc-rs`
- `ring`

## Notes

This documentation is derived from the current `src/` implementation. If the implementation changes, treat the source code as authoritative.
