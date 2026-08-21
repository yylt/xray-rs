# AGENTS.md

## Build

使用 make 目标构建（debug），**不主动构建 release 版本**——release 由 CI/release 流程负责。

```bash
make build-xray   # debug build xray-rs binary
make build-rsdns  # debug build rsdns binary
```

- `target/release/xray-rs` and `target/release/rsdns` are the two binaries (built by CI/release, not by hand).

## Lint & Test

```bash
make ci      # run fmt + clippy + check + test
```

- `make ci` 是本地完整校验入口（fmt → clippy → workspace check → test），改动后必须通过。
- 不主动做 smoke test / 手工起服务验证；只需通过 `make ci`。

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

- Source: `src/bin/rsdns/`. Entry: `main.rs`. Modules: `config.rs`, `server.rs`, `query.rs`, `metrics.rs`, `plugins/` (stages), `upstream/` (connection + pool + groups).
- **Listeners (inbound)**: UDP (`ip:port`) and TCP (`tcp://ip:port`), configured via `binds[]`.
- **Upstream protocols (outbound)**: plain UDP/TCP, DoT (`tls://`), DoH (`https://`), DoH3 (`h3://`), DoQ (`quic://`).
- **Query pipeline** (`server.rs:handle_query`): fixed stages `hosts → groups → cache → rules`; `upstream` is **not** a stage — it is assembled at startup into `upstream::Upstreams` (a concrete type holding the named groups) and held directly by the `rules` stage for forward/cname; fallback returns NXDOMAIN/SERVFAIL.
  - **Cache records**: A, AAAA, CNAME, MX, TXT, and HTTPS are cached. NXDOMAIN is negatively cached. Stale hits (serve_expired) continue through the pipeline so rules can replace them with a fresh upstream answer. Hosts and block responses are never cached.
- **Rules**: ordered by priority. Actions: `block` (NXDomain or poison IP), `cname` (rewrite + recursive resolve), `forward` (named upstream pool, optional TTL override).
- **Cache**: LRU with configurable capacity, TTL clamping, serve-expired with in-pipeline refresh.
- **Connection pool**: adaptive weighted address selection, cooldown on failure, SOA health probes, per-address-family preference.

## Rules

- **No annotation bypasses**: Do not suppress warnings/errors with `#[allow(...)]`, `#[cfg(...)]` hacks, or other annotation-based workarounds. Fix the root cause instead.
- **先思考** — 明确假设。如有疑问，先问。
- **简洁** — 最少代码。不为单次使用引入抽象。不添加未请求的功能。
- **精确** — 只动必须改的。保持现有风格。只删自己留下的孤儿代码。
- **目标驱动** — 先定义成功标准。验证后再声明完成。
- **提案先行** — 任何重大修改（新增功能、API 变更、架构调整等）必须先提交提案文档到 `docs/design/` 进行审阅，审阅通过后再进行实现。
