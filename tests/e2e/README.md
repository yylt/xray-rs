# E2E Tests

端到端（End-to-End）测试，验证 xray-rs 二进制在真实网络环境中的完整链路行为。

## 技术方案

测试框架使用 **Go** 编写（`main.go`），通过 `os/exec` 启动 xray-rs 子进程，构造请求并校验响应。

- **xray 测试**：采用 server/client 对开模式——先启动服务端（trojan inbound），再启动客户端（http/socks inbound → trojan outbound），客户端通过代理访问公网目标（baidu.com）来验证链路通畅。
- **rsdns 测试**：已随 rsdns 迁移至独立仓库（`rsdns/tests/e2e/`），见该仓库文档。

## 目录结构

```
tests/e2e/
├── README.md                  # 本文件
├── main.go                    # 入口 + 公共工具函数（进程管理、端口等待、HTTP/SOCKS5 探测）
├── go.mod                     # Go module 定义
├── run_xray_tests.sh          # xray 测试启动脚本
├── test_ws_trojan.go          # WebSocket+TLS+Trojan 测试
├── test_grpc_tls_trojan.go    # gRPC+TLS+Trojan 测试
├── test_core_compat.go        # Core 兼容测试及共享证书/JSON 配置生成
├── test_xhttp_caddy.go        # TLS Caddy reverse_proxy XHTTP 测试
└── configs/
    ├── ws-tls-server.yaml     # WS+TLS 服务端配置
    ├── ws-tls-client.yaml     # WS+TLS 客户端配置
    ├── grpc-tls-server.yaml   # gRPC+TLS 服务端配置
    └── grpc-tls-client.yaml   # gRPC+TLS 客户端配置
```

## 前置条件

| 依赖 | 用途 |
|------|------|
| **Go** ≥ 1.21 | 编译和运行测试 |
| **Cargo** | 确保 Rust 工具链可用（实际二进制需预先构建） |
| `target/debug/xray-rs` 或 `target/release/xray-rs` | xray 测试所需二进制 |
| **Caddy**（`caddy` 在 PATH） | XHTTP TLS reverse_proxy 测试必需，缺失时失败，不跳过；已验证 v2.11.9，建议使用该版本官方二进制 |
| **网络** | WS/gRPC/Core 测试需能访问公网 baidu.com；XHTTP Caddy 测试仅访问本地 HTTP/HTTPS 源站 |

## 运行方式

```bash
# 构建 debug 二进制并运行 E2E 测试（在仓库根目录执行）
make e2e

# 若已构建二进制，也可直接运行
./tests/e2e/run_xray_tests.sh

# 仅运行 XHTTP Caddy 矩阵（-test 为不区分大小写的套件名子串）
./tests/e2e/run_xray_tests.sh -test XHTTP
```

## Xray-Core 双向兼容测试

```bash
# 默认使用相邻仓库 ../Xray-Core/xray；同时运行原生 E2E 和兼容 E2E
make e2e-compat

# 也可指定已构建的 Xray-Core 二进制（必须存在，缺失时报错而非跳过）
make e2e-compat XRAY_CORE_BIN=/absolute/path/to/xray
```

兼容矩阵为 WS / gRPC + TLS + Trojan，各自覆盖 Core client → Rust server、Rust client → Core server，
每个组合验证 HTTP GET、HTTP CONNECT 和 SOCKS5。加上原生 WS/gRPC、XHTTP Caddy 测试及
HTTP inbound → SOCKS5 outbound → Core SOCKS5 inbound 链路测试共 9 个套件。
测试临时生成 localhost 证书及双方原生 JSON 配置，结束后回收进程并清理临时文件。
Core 客户端通过 `pinnedPeerCertSha256` 校验证书；Rust 测试客户端使用 `allowInsecure`。
兼容测试使用本机端口 14001–14003，链路测试使用 16001–16002，需保持空闲；不并行运行多个实例。

PR 的 `E2E xray-rs` check 构建固定上游 Xray-Core v26.10.21
（`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`）并运行 `make e2e-compat`。
本地相邻仓库的二进制可能包含 fork 修改，其结果不等同于固定上游版本的验证结果。
仍需要公网访问 baidu.com / example.com；TCP 就绪探测产生的握手 EOF 不代表实际代理请求失败。

## 测试套件详解

**测试模式**：Server/Client 对开

```
┌─────────────┐          ┌─────────────┐          ┌──────────┐
│   Client    │  trojan  │   Server    │          │  Public  │
│ (http/socks)│ ──────→  │  (trojan)   │ ──────→  │ Internet │
│             │   TLS    │             │ freedom  │          │
└─────────────┘          └─────────────┘          └──────────┘
```

### WebSocket+TLS+Trojan（`test_ws_trojan.go`）

1. 启动服务端（`configs/ws-tls-server.yaml`），监听 `127.0.0.1:11001`（trojan + ws + tls）
2. 等待端口 11001 就绪
3. 启动客户端（`configs/ws-tls-client.yaml`），暴露 `127.0.0.1:12001`（http inbound）和 `127.0.0.1:12002`（socks inbound），outbound 指向服务端
4. HTTP 代理（12001）分别测试普通 GET（`http://baidu.com`，禁止跟随重定向）和 CONNECT 隧道（`https://www.baidu.com`，校验 CONNECT 返回 200）
5. GET 校验状态码 200 或带 Location 的 301/302/307/308，CONNECT 内的 HTTPS GET 校验 200；两者均要求响应体非空
6. SOCKS5 代理（12002）请求 `http://baidu.com`，校验最终 HTTP 状态码 200

### gRPC+TLS+Trojan（`test_grpc_tls_trojan.go`）

1. 启动服务端（`configs/grpc-tls-server.yaml`），监听 `127.0.0.1:11002`（trojan + grpc + tls）
2. 等待端口 11002 就绪
3. 启动客户端（`configs/grpc-tls-client.yaml`），暴露 `127.0.0.1:13001`（http inbound）和 `127.0.0.1:13002`（socks inbound）
4. HTTP 代理（13001）执行与 WebSocket 套件相同的独立 GET 和 CONNECT 测试，校验状态码及响应体非空
5. SOCKS5 代理（13002）请求 `http://baidu.com`，校验最终 HTTP 状态码 200

### XHTTP + TLS Caddy reverse_proxy（`test_xhttp_caddy.go`）

- 仅覆盖 Caddy 反向代理链路，不运行直连 XHTTP E2E。
- 矩阵为 Caddy upstream HTTP/1.1 / h2c，共 2 个套件；客户端/服务端均省略 `mode`，验证默认 packet-up。
- Rust 客户端拨号 `127.0.0.1:15002`，使用 TLS SNI 和 HTTP authority `localhost`，ALPN 为 `h2`；Caddy 的站点为 `https://localhost:15002`，反向代理至明文 XHTTP 后端 `127.0.0.1:15001`。
- 每个组合先验证本地小响应在源站 EOF 前到达，再通过客户端 HTTP 代理 `127.0.0.1:15003` 向本地 HTTP/HTTPS 源站上传大请求体并逐字节校验回显（HTTPS 使用 CONNECT）。不访问公网。
- 复用 Core 兼容测试的临时 localhost 自签名证书与 JSON 配置生成函数；Rust 客户端使用 `allowInsecure`。不使用 Caddy 内部 CA，不修改系统信任。
- 结束或失败时终止并回收所有子进程、删除临时目录；Caddy 的 XDG config/data 也隔离在该目录。端口 15001–15003 需空闲，不并行运行多个实例。
- CI 的 E2E workflow 固定下载官方 Caddy v2.11.9，并用发行版 checksums 文件校验 SHA-512 后运行完整矩阵。较旧发行版的 Caddy/Go 可能缺少 HTTP/1 全双工支持，不建议使用；缺失 Caddy 会计为失败，不会静默跳过。

### HTTP inbound → SOCKS5 outbound → Core SOCKS5 inbound（`test_http_socks_chain.go`）

- 链路：Rust HTTP inbound（`127.0.0.1:16002`）→ Rust SOCKS5 outbound → Xray-Core SOCKS5 inbound（`127.0.0.1:16001`）→ Core freedom 出站 → 公网。
- 通过 HTTP 代理 GET `http://example.com`，校验状态码 200 且正文包含 `Example Domain`（确认响应来自目标站点而非错误页）。
- 再通过同一代理 CONNECT `https://example.com`，校验隧道建立、状态码 200 及正文包含 `Example Domain`。
- 仅在提供 `-core` 时运行（需要 Xray-Core 二进制）；端口 16001–16002 需空闲，不并行运行多个实例。

### 通用工具函数（`main.go`）

| 函数 | 用途 |
|------|------|
| `startServer(ctx, configPath)` | 启动 xray-rs 子进程，返回 `*Process` |
| `Process.Stop()` | 通过 SIGKILL 终止子进程 |
| `waitForPort(port, timeout)` | 轮询 TCP 端口直到监听成功 |
| `testHTTPProxy(port)` | 分别验证 HTTP GET（不跟随重定向）和 HTTPS CONNECT 隧道 |
| `testSOCKS5Proxy(port)` | 通过 SOCKS5 代理请求 `http://baidu.com` |
| `testFreedom(targetURL)` | 直连请求（freedom outbound 验证） |
| `testExampleDomain(port)` | 经 HTTP 代理 GET/CONNECT `example.com`，校验响应来自目标站点 |
