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
# 先构建二进制
cargo build --bin xray-rs

# 运行 E2E 测试
./tests/e2e/run_xray_tests.sh
```

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
4. 通过 HTTP 代理（12001）和 SOCKS5 代理（12002）分别请求 `http://baidu.com`
5. 校验 HTTP 状态码 200 及响应体非空

### gRPC+TLS+Trojan（`test_grpc_tls_trojan.go`）

1. 启动服务端（`configs/grpc-tls-server.yaml`），监听 `127.0.0.1:11002`（trojan + grpc + tls）
2. 等待端口 11002 就绪
3. 启动客户端（`configs/grpc-tls-client.yaml`），暴露 `127.0.0.1:13001`（http inbound）和 `127.0.0.1:13002`（socks inbound）
4. 通过 HTTP 代理和 SOCKS5 代理分别请求 `http://baidu.com`
5. 校验 HTTP 状态码 200 及响应体非空

### 通用工具函数（`main.go`）

| 函数 | 用途 |
|------|------|
| `startServer(ctx, configPath)` | 启动 xray-rs 子进程，返回 `*Process` |
| `Process.Stop()` | 通过 SIGKILL 终止子进程 |
| `waitForPort(port, timeout)` | 轮询 TCP 端口直到监听成功 |
| `testHTTPProxy(port)` | 通过 HTTP 代理请求 `http://baidu.com` |
| `testSOCKS5Proxy(port)` | 通过 SOCKS5 代理请求 `http://baidu.com` |
| `testFreedom(targetURL)` | 直连请求（freedom outbound 验证） |
