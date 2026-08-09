# AGENTS.md

## Build

```bash
cargo build -r                         # release (default features: aws-lc-rs, mimalloc, tun)
cargo build --no-default-features      # no tun/mimalloc/aws-lc-rs
cargo run -- run -c config.yaml        # run proxy
cargo run --bin rsdns -- -c rsdns.yaml # run DNS server
```

- `target/release/xray-rs` and `target/release/rsdns` are the two binaries.
- Cross-compilation uses [`cross`](https://github.com/cross-rs/cross); see `Cross.toml` for target images.

## Lint & Test

```bash
cargo fmt    # edition = 2024, max_width = 120, fn_call_width = 80
cargo test   # runs unit tests
```

- E2E tests live in `tests/e2e/` and require **Go** + a pre-built `xray-rs` binary at `target/release/xray-rs`. Run: `./tests/e2e/run_tests.sh`.

## Code Generation

```bash
make tools    # installs protoc-gen-prost + protoc-gen-tonic (one-time)
make generate # regenerates src/generated/grpc_generated.rs from proto/grpc_transport.proto
```

Do **not** hand-edit `src/generated/grpc_generated.rs`.

## Architecture (high-signal)

- **Single crate** (not a workspace). `src/main.rs` for `xray-rs`, `src/bin/rsdns/` for the DNS binary.
- **Config format**: YAML by default (`.yaml`/`.yml`), JSON also supported. Config struct at `src/command/run.rs:Config`.
- **Startup flow** (`src/command/run.rs:run_proxy`): DNS init → outbound sinks → router → inbound listeners → forwarding loop.
- **Inbounds** produce `ProxyStream`s. **Router** picks an outbound tag via domain/IP/inboundTag rules. **Outbound sink** connects and pipes traffic via `StreamForwarder`.
- **`src/common/forward.rs`**: `StreamForwarder` uses `tokio::io::copy_bidirectional` by default, `libc::splice` zero-copy on `linux/android`.
- **`src/proxy/reverse.rs`**: reverse proxy (p2p tunnel), daemon-mode only.
- **`src/proxy/api.rs`**: management API inbound (requires router + stats + sinks deps).
- **Generated gRPC**: re-exported as `xray_rs::grpc_transport`.

## rsdns (DNS Binary)

- Source: `src/bin/rsdns/`. Entry: `main.rs`. Modules: `config.rs`, `server.rs`, `rule.rs`, `upstream.rs`, `conn.rs`, `cache.rs`, `hosts.rs`, `factory.rs`, `pool.rs`.
- **Listeners (inbound)**: UDP (`ip:port`) and TCP (`tcp://ip:port`), configured via `bind[]`.
- **Upstream protocols (outbound)**: plain UDP/TCP, DoT (`tls://`), DoH (`https://`), DoH3 (`h3://`), DoQ (`quic://`).
- **Query pipeline** (`server.rs:do_query`): hosts → cache → rules → upstream; fallback returns NXDOMAIN.
- **Rules**: ordered by priority. Actions: `block` (NXDomain or poison IP), `cname` (rewrite + recursive resolve), `forward` (named upstream pool, optional cache bypass/TTL override).
- **Cache**: LRU with configurable capacity, TTL clamping, serve-expired with background refresh.
- **Connection pool**: adaptive weighted address selection, cooldown on failure, SOA health probes, per-address-family preference.
- Example config: `example/rsdns-all-example.yaml` (covers all features).
- E2E tests: `tests/e2e/test_rsdns.go`, `tests/e2e/run_rsdns_tests.sh`.

## Platform Notes

- Unix domain sockets: only behind `#[cfg(unix)]` in `src/transport/raw.rs`.
- `tun` feature: gated behind `#[cfg(feature = "tun")]` in `src/proxy/tun.rs`. Default on.
- Windows: builds with `--no-default-features --features mimalloc,ring --profile release-with-symbols` (unix sockets + tun unavailable).

## Release

CI (`release.yaml`) builds 4 targets: x86_64-linux-musl, aarch64-linux-musl, aarch64-linux-android, x86_64-windows-msvc. Release packaging uses goreleaser with a Go stub (`goreleaser.go`) and `goreleaser_hook.sh` to swap in Rust-built binaries.

## Config Reference

See `example/` directory for working configs: TCP/Trojan, gRPC/Trojan, gRPC+TLS/Trojan, WebSocket/Trojan, load-balancer with fallback.

## Testing

- Unit tests: `cargo test` (Rust native, spread across `src/`).
- E2E tests: live under `tests/e2e/`, require **Go** + a pre-built `xray-rs` binary at `target/release/xray-rs`. Run: `./tests/e2e/run_tests.sh`.

## Rules

- **No annotation bypasses**: Do not suppress warnings/errors with `#[allow(...)]`, `#[cfg(...)]` hacks, or other annotation-based workarounds. Fix the root cause instead.
