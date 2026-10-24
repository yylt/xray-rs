# AGENTS.md

## Build

使用 make 目标构建（debug），**不主动构建 release 版本**——release 由 CI/release 流程负责。

```bash
make build-xray  # debug build xray-rs binary
```

- `target/release/xray-rs` is the release binary (built by CI/release, not by hand).
- rsdns 已独立为 `rsdns/` 子仓库（独立 crate），不再在本仓库内构建。

## Lint & Test

```bash
make ci      # run fmt + clippy + check + test
```

- `make ci` 是本地完整校验入口（fmt → clippy → workspace check → test）。**任何代码改动后都必须执行 `make ci`，并修复其中所有问题，直到完全健康**——即 exit 0、打印 `CI: all checks passed`、clippy 零警告、测试全绿。
- `clippy` 以 `-D warnings` 运行（`cargo clippy --workspace --all-targets -- -D warnings`），任何 warning 都会升级为编译错误；出现弃用/告警必须修根因，不得用 `#[allow(...)]` 掩盖（见 Rules）。
- `cargo fmt` 是 `make ci` 的一环，会自动格式化并应产生零 diff；提交前 `git diff` 中不应出现仅由 fmt 产生的格式改动。
- 不主动做 smoke test / 手工起服务验证；只需通过 `make ci`。

## Code Generation

```bash
make tools    # installs protoc-gen-prost + protoc-gen-tonic (one-time)
make generate # regenerates src/generated/grpc_generated.rs from proto/grpc_transport.proto
```

Do **not** hand-edit `src/generated/grpc_generated.rs`.

## Architecture (high-signal)

- **Single crate** (not a workspace). `src/main.rs` for `xray-rs`. rsdns 已独立为 `rsdns/` 子仓库（见 `rsdns/AGENTS.md`）。
- **Config format**: YAML by default (`.yaml`/`.yml`), JSON also supported. Config struct at `src/command/run.rs:Config`.
- **Startup flow** (`src/command/run.rs:run_proxy`): DNS init → outbound sinks → router → inbound listeners → forwarding loop.
- **Inbounds** produce `ProxyStream`s. **Router** picks an outbound tag via domain/IP/inboundTag rules. **Outbound sink** connects and pipes traffic via `StreamForwarder`.
- **`src/common/forward.rs`**: `StreamForwarder` uses `tokio::io::copy_bidirectional` by default, `libc::splice` zero-copy on `linux/android`.
- **`src/proxy/reverse.rs`**: reverse proxy (p2p tunnel), daemon-mode only.
- **`src/proxy/api.rs`**: management API inbound (requires router + stats + sinks deps).
- **Generated gRPC**: re-exported as `xray_rs::grpc_transport`.

## Rules

- **No annotation bypasses**: Do not suppress warnings/errors with `#[allow(...)]`, `#[cfg(...)]` hacks, or other annotation-based workarounds. Fix the root cause instead.
- **先思考** — 明确假设。如有疑问，先问。
- **简洁** — 最少代码。不为单次使用引入抽象。不添加未请求的功能。
- **精确** — 只动必须改的。保持现有风格。只删自己留下的孤儿代码。
- **目标驱动** — 先定义成功标准。验证后再声明完成。
- **提案先行** — 任何重大修改（新增功能、API 变更、架构调整等）必须先提交提案文档到 `docs/design/` 进行审阅，审阅通过后再进行实现。
