# xray-rs

Default language: English | [中文](./README.md)

A lightweight proxy core implemented in Rust, with composable inbound, outbound, routing, DNS, and transport capabilities.

## Features

- Inbounds: `http`, `socks`, `trojan`, `vless`, `reverse`
- Outbounds: `freedom`, `blackhole`, `socks`, `trojan`, `vless`, `reverse`
- Routing: supports `domain`, `ip`, `inboundTag`, and fallback
- Transport: supports `tcp`, `ws`, `grpc`, with optional `tls`
- DNS: built-in `DnsResolver` (the standalone `rsdns` binary has moved to its own repository)

## Quick Start

### Build

```bash
cargo build --release
```

Produces:

- `target/release/xray-rs`

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

`run` accepts a tokio runtime thread-mode option (default `single`):

```bash
xray-rs run -c config.yaml --thread single
xray-rs run -c config.yaml --thread multi
```

## Minimal config example

```yaml
log:
  file: /var/log/xray-rs.log   # optional, defaults to stderr
  level: info                  # optional, off|error|warn|info|debug|trace, default info

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
```

DNS uses only the system resolver, with no application DNS cache or `dns` configuration. Remove the legacy field. System DNS/hosts and caching are managed by the OS.

### freedom address preference and connection retry

```yaml
outbounds:
  - tag: direct
    protocol: freedom
    settings:
      prefer: ipv4              # system (default) | ipv4 | ipv6
      connectTimeoutMs: 5000    # default 5000; positive integer
      bpf: false
```

`prefer` orders the system DNS results without excluding the other address family. Order within each family is preserved and duplicate IPs are removed. A domain is resolved once; failed or timed-out connections advance to the next IP, once per address. The per-address timeout includes transport handshakes, not forwarding idle time. DNS retains the system resolver's timeout semantics; total connection time may grow with the number of candidates. Literal IPs also use the connection timeout.

No reconnect or application-data replay occurs after connection establishment, including on TLS errors. UDP retries only local connect failures: successful UDP connect does not prove remote reachability or provide datagram-level failover.

HTTP CONNECT sends `200 Connection Established` only after the outbound connection succeeds; connection failures return `502`, and explicit timeouts return `504`. It does not wait for client TLS inside the tunnel. For chained proxies, success is limited to the connection stage that the outbound protocol can confirm. Library users of `ConnectionSink::handle` get automatic responses; custom forwarding that extracts `ProxyStream.inner` / `into_inner()` must first call `confirm_connected()` after outbound success, or `reject_connection()` on failure.

### log config

- `file`: path of the log file (append mode). When omitted, logs go to stderr.
- `level`: filter level `off|error|warn|info|debug|trace`, default `info`.

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

## rsdns

The standalone DNS server has moved to its own repository: [`rsdns`](https://github.com/yylt/xray-rs/tree/main/rsdns) (the `rsdns/` directory is an independent crate with its own README, CI, tests, and design docs).

## Notes

This documentation is derived from the current `src/` implementation. If the implementation changes, treat the source code as authoritative.
