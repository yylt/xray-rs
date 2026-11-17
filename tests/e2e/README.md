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
| **网络** | 需要能访问公网（baidu.com、223.5.5.5 等），xray 测试会通过代理请求公网 |

## 运行方式

```bash
# 构建 debug 二进制并运行 E2E 测试（在仓库根目录执行）
make e2e

# 若已构建二进制，也可直接运行
./tests/e2e/run_xray_tests.sh
```

## Xray-Core 双向兼容测试

```bash
# 默认使用相邻仓库 ../Xray-Core/xray；同时运行原生 E2E 和兼容 E2E
make e2e-compat

# 也可指定已构建的 Xray-Core 二进制（必须存在，缺失时报错而非跳过）
make e2e-compat XRAY_CORE_BIN=/absolute/path/to/xray
```

兼容矩阵为 WS / gRPC + TLS + Trojan，各自覆盖 Core client → Rust server、Rust client → Core server，
每个组合验证 HTTP GET、HTTP CONNECT 和 SOCKS5。加上原生测试共 6 个套件。
测试临时生成 localhost 证书及双方原生 JSON 配置，结束后回收进程并清理临时文件。
Core 客户端通过 `pinnedPeerCertSha256` 校验证书；Rust 测试客户端使用 `allowInsecure`。
兼容测试使用本机端口 14001–14003，需保持空闲；不并行运行多个实例。

PR 的 `E2E xray-rs` check 构建固定上游 Xray-Core v26.10.21
（`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`）并运行 `make e2e-compat`。
本地相邻仓库的二进制可能包含 fork 修改，其结果不等同于固定上游版本的验证结果。
仍需要公网访问 baidu.com；TCP 就绪探测产生的握手 EOF 不代表实际代理请求失败。

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

### 通用工具函数（`main.go`）

| 函数 | 用途 |
|------|------|
| `startServer(ctx, configPath)` | 启动 xray-rs 子进程，返回 `*Process` |
| `Process.Stop()` | 通过 SIGKILL 终止子进程 |
| `waitForPort(port, timeout)` | 轮询 TCP 端口直到监听成功 |
| `testHTTPProxy(port)` | 分别验证 HTTP GET（不跟随重定向）和 HTTPS CONNECT 隧道 |
| `testSOCKS5Proxy(port)` | 通过 SOCKS5 代理请求 `http://baidu.com` |
| `testFreedom(targetURL)` | 直连请求（freedom outbound 验证） |
