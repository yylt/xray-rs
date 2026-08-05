# E2E Tests

端到端（End-to-End）测试，验证 xray-rs 和 rsdns 二进制在真实网络环境中的完整链路行为。

## 技术方案

测试框架使用 **Go** 编写（`main.go`），通过 `os/exec` 启动 xray-rs / rsdns 子进程，构造请求并校验响应。

- **xray 测试**：采用 server/client 对开模式——先启动服务端（trojan inbound），再启动客户端（http/socks inbound → trojan outbound），客户端通过代理访问公网目标（baidu.com）来验证链路通畅。
- **rsdns 测试**：启动 rsdns 进程，使用原始 UDP DNS wire-format 查询，验证转发、拦截、缓存、hosts 等核心功能。

## 目录结构

```
tests/e2e/
├── README.md                  # 本文件
├── main.go                    # 入口 + 公共工具函数（进程管理、端口等待、HTTP/SOCKS5 探测）
├── go.mod                     # Go module 定义
├── run_xray_tests.sh          # xray 测试启动脚本
├── run_rsdns_tests.sh         # rsdns 测试启动脚本
├── test_ws_trojan.go          # WebSocket+TLS+Trojan 测试
├── test_grpc_tls_trojan.go    # gRPC+TLS+Trojan 测试
├── test_rsdns.go              # rsdns 全功能测试（转发/拦截/缓存/hosts/DoT/DoH/DoH3）
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
| `target/debug/rsdns` 或 `target/release/rsdns` | rsdns 测试所需二进制 |
| **网络** | 需要能访问公网（baidu.com、223.5.5.5 等），xray 测试会通过代理请求公网 |

## 运行方式

### 全部测试

```bash
# 先构建二进制
cargo build --bin xray-rs --bin rsdns

# 运行全部 E2E 测试
./tests/e2e/run_tests.sh
```

### 仅 xray 测试

```bash
./tests/e2e/run_xray_tests.sh
```

### 仅 rsdns 测试

```bash
./tests/e2e/run_rsdns_tests.sh
```

## 测试套件详解

### 1. xray 测试（`suite=xray`）

**测试模式**：Server/Client 对开

```
┌─────────────┐          ┌─────────────┐          ┌──────────┐
│   Client    │  trojan  │   Server    │          │  Public  │
│ (http/socks)│ ──────→  │  (trojan)   │ ──────→  │ Internet │
│             │   TLS    │             │ freedom  │          │
└─────────────┘          └─────────────┘          └──────────┘
```

#### WebSocket+TLS+Trojan（`test_ws_trojan.go`）

1. 启动服务端（`configs/ws-tls-server.yaml`），监听 `127.0.0.1:11001`（trojan + ws + tls）
2. 等待端口 11001 就绪
3. 启动客户端（`configs/ws-tls-client.yaml`），暴露 `127.0.0.1:12001`（http inbound）和 `127.0.0.1:12002`（socks inbound），outbound 指向服务端
4. 通过 HTTP 代理（12001）和 SOCKS5 代理（12002）分别请求 `http://baidu.com`
5. 校验 HTTP 状态码 200 及响应体非空

#### gRPC+TLS+Trojan（`test_grpc_tls_trojan.go`）

1. 启动服务端（`configs/grpc-tls-server.yaml`），监听 `127.0.0.1:11002`（trojan + grpc + tls）
2. 等待端口 11002 就绪
3. 启动客户端（`configs/grpc-tls-client.yaml`），暴露 `127.0.0.1:13001`（http inbound）和 `127.0.0.1:13002`（socks inbound）
4. 通过 HTTP 代理和 SOCKS5 代理分别请求 `http://baidu.com`
5. 校验 HTTP 状态码 200 及响应体非空

### 2. rsdns 测试（`suite=rsdns`）

rsdns 测试使用**原始 UDP DNS wire-format query**，不依赖系统 DNS 解析器，直接向 `127.0.0.1:<port>` 发送 DNS 请求。

#### 端口分配

| 测试 | 端口 | 说明 |
|------|------|------|
| Forward | 15353 | DNS 转发 + 广告域名 poison 拦截 |
| Hosts | 15354 | hosts 静态记录生效验证 |
| Cache | 15355 | 缓存命中（首次 vs 二次查询延迟对比） |
| DoT | 15356 | DNS over TLS 上游（需 `RSDNS_UPSTREAM_DOT`） |
| DoH | 15357 | DNS over HTTPS 上游（需 `RSDNS_UPSTREAM_DOH`） |
| DoH3 | 15358 | DNS over HTTP/3 上游（需 `RSDNS_UPSTREAM_DOH3`） |
| Reject | 15359 | NXDOMAIN 拦截验证 |

#### 测试内容

| 测试 | 验证点 |
|------|--------|
| **Forward** | `example.com` 可正常解析；`track.doubleclick.net` 返回 `0.0.0.0`（poison 拦截） |
| **Hosts** | `rsdns-test-blocked.example.com` 命中 hosts 记录，返回 `0.0.0.0` |
| **Cache** | 首次查询 `www.baidu.com` 后，二次查询直接命中缓存 |
| **Reject** | `blocked-nxdomain.example` 返回 NXDOMAIN（无解析结果） |
| **DoT** | 通过 TLS 上游解析 `example.com`；非匹配域名无法解析（验证分流无泄漏） |
| **DoH** | 通过 DoH 上游解析 `example.com`；非匹配域名无法解析（验证分流无泄漏） |
| **DoH3** | 通过 HTTP/3 上游解析 `example.com`；非匹配域名无法解析（验证分流无泄漏） |

> DoT/DoH/DoH3 采用**分流校验**模式：配置双 upstream——`test` 指向协议上游，`default` 指向不可达地址 `127.0.0.1:19999`。规则将 `example.com` 路由到 `test`，其余走 `default`。校验匹配域名解析成功、非匹配域名解析失败，以此确认分裂未泄漏到默认路由。

### 环境变量（rsdns 可选测试）

| 变量 | 说明 | 示例 |
|------|------|------|
| `RSDNS_UPSTREAM_DOT` | DoT 上游地址（host:port） | `1.1.1.1:853` |
| `RSDNS_UPSTREAM_DOH` | DoH 上游 URL | `https://1.1.1.1/dns-query` |
| `RSDNS_UPSTREAM_DOH3` | DoH3 上游 URL | `https://1.1.1.1/dns-query` |

### 通用工具函数（`main.go`）

| 函数 | 用途 |
|------|------|
| `startServer(ctx, configPath)` | 启动 xray-rs 子进程，返回 `*Process` |
| `Process.Stop()` | 通过 SIGKILL 终止子进程 |
| `waitForPort(port, timeout)` | 轮询 TCP 端口直到监听成功 |
| `testHTTPProxy(port)` | 通过 HTTP 代理请求 `http://baidu.com` |
| `testSOCKS5Proxy(port)` | 通过 SOCKS5 代理请求 `http://baidu.com` |
| `testFreedom(targetURL)` | 直连请求（freedom outbound 验证） |
