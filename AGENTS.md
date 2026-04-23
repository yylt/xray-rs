# AGENTS.md - xray-rs Development Guide

## Project Overview

Lightweight proxy core (xray) implemented in Rust with composable inbound, outbound, routing, DNS, and transport layers.

**Binaries:** `xray-rs` (main), `rsdns` (DNS resolver)

## Build / Test / Lint Commands

### Essential Commands

```bash
# Build (release)
cargo build --release

# Build specific binary
cargo build --release --bin xray-rs
cargo build --release --bin rsdns

# Run (dev)
cargo run -- run -c config.yaml

# Run tests
cargo test                           # all tests
cargo test <test_name>               # single test by name
cargo test --package xray-rs --lib   # unit tests only
cargo test --test <name>             # integration test
cargo test -- --test-threads=1       # sequential execution

# Format code
cargo fmt
make fmt

# Check compilation
cargo check
make check
```

### Feature Flags

```bash
# Default features: aws-lc-rs, jemalloc, tun
cargo build --release

# Without default features
cargo build --release --no-default-features

# Specific feature
cargo build --release --features mimalloc
cargo build --features tun
```

### E2E Tests (Go-based)

```bash
cd tests/e2e && ./run_tests.sh
```

### gRPC Code Generation

```bash
make tools        # install protoc-gen-prost, protoc-gen-tonic
make generate     # regenerate from proto/grpc_transport.proto
```

## Code Style Guidelines

### Rust Edition & Formatting

- **Edition**: 2021 (`Cargo.toml`)
- **rustfmt Edition**: 2024 (`rustfmt.toml`)
- **max_width**: 120
- **fn_call_width**: 80

### Imports

- Group imports: `std::`, external crates, internal modules
- Use `crate::` for internal module references
- Sort imports alphabetically within groups

```rust
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;

use crate::common::*;
use crate::transport::TrStream;
```

### Naming Conventions

- **Modules/files**: `snake_case` (`trojan.rs`, `stream_settings.rs`)
- **Types/structs/enums**: `PascalCase` (`InboundSettings`, `ProxyStream`, `Outbounder`)
- **Functions/methods**: `snake_case` (`new()`, `connect()`, `run()`, `deserialize_settings()`)
- **Variables**: `snake_case` (`dns_resolver`, `server_addr`)
- **Constants**: `UPPER_SNAKE_CASE` (`GLOBAL`, `PROFILE`)
- **Serde rename**: `camelCase` for JSON/YAML fields (`#[serde(rename = "allowTransparent")]`)

### Error Handling

- **Use `std::io::Result`** for network/proxy operations
- **Use `thiserror`** for custom error types
- **Create errors with `tokio::io::Error`** for simple cases:
  ```rust
  Err(tokio::io::Error::new(
      tokio::io::ErrorKind::Other,
      "descriptive error message".to_string(),
  ))
  ```
- **Pattern match on `Result`** explicitly at boundaries:
  ```rust
  match root::execute() {
      Err(e) => println!("execute error: {e}"),
      _ => {}
  }
  ```

### Types & Serde

- **Derive macros**: `#[derive(Serialize, Deserialize, Debug)]`
- **Tagged enums**: Use `#[serde(tag = "protocol", content = "settings")]` for protocol dispatch
- **Default handling**: Deserializers should handle missing fields with defaults
- **Feature-gated variants**: `#[cfg(feature = "tun")]` on enum variants and modules

### Async Patterns

- **Runtime**: Tokio with `sync`, `net`, `fs`, `time`, `signal` features
- **Stream handling**: Use `BoxStream` from `futures` for stream returns
- **Arc for shared state**: `std::sync::Arc<T>` for thread-safe sharing
- **Common pattern**: `new()` constructors return `Result<Self>`

### Module Structure

```
src/
├── main.rs           # Entry point, logging setup
├── lib.rs            # Module declarations, public exports
├── build.rs          # Git/version info generation
├── app/              # Application layer (source/sink)
├── command/          # CLI commands (run, version, root)
├── common/           # Shared utilities (trie, parse, socks, sniff, tls, stats)
├── proxy/            # Protocol implementations
│   ├── http.rs
│   ├── socks.rs
│   ├── trojan.rs
│   ├── vless.rs
│   ├── reverse.rs
│   └── tun.rs        # feature-gated
├── route/            # Routing & DNS resolution
│   ├── router.rs
│   ├── dns.rs
│   ├── resolver.rs
│   ├── matcher.rs
│   └── cache.rs
├── transport/        # Transport layer
│   ├── raw.rs        # TCP
│   ├── websocket.rs
│   ├── grpc.rs
│   ├── tls.rs
│   └── balancer.rs
└── generated/        # Auto-generated gRPC code
```

### Testing

- **Unit tests**: `#[cfg(test)] mod tests { ... }` at module bottom
- **Test naming**: Descriptive, function-style: `deserialize_http_inbound_without_settings_uses_defaults()`
- **Serialization tests**: Verify JSON/YAML parsing with and without optional fields
- **Feature-gated tests**: Use `#[cfg(not(feature = "tun"))]` for negative testing

### Logging

- **Framework**: `env_logger` + `log` crate
- **Custom format**: `{LevelLetter}{MMDD} {target}] {message}`
- **Default level**: `Info`
- **Log at startup**: Git commit, branch, rustc version, build target/profile

### Performance

- **Allocators**: Choice between `jemalloc` (default) or `mimalloc` via features
- **Release profile**: LTO enabled, strip symbols, single codegen unit
- **Linux optimizations**: `libc::splice` for zero-copy forwarding on linux/android
- **Platform detection**: Use `#[cfg(unix)]`, `#[cfg(target_os = "linux")]`

### Dependencies (Key)

| Category | Crates |
|----------|--------|
| Runtime | `tokio`, `futures`, `async-stream` |
| Serialization | `serde`, `serde_json`, `serde_yaml` |
| Network | `hyper`, `tonic`, `tower`, `tokio-tungstenite` |
| TLS/Crypto | `rustls`, `tokio-rustls`, `ring`, `aws-lc-rs` |
| CLI | `clap` (derive) |
| DNS | `hickory-resolver`, `hickory-proto` |
| Proto | `prost`, `tonic-prost` |
| Errors | `thiserror` |
| Utils | `bytes`, `uuid`, `base64`, `parking_lot`, `ahash` |
