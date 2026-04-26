# xray-rs 项目指南

## 项目概述

**xray-rs** 是一个使用 Rust 实现的轻量级代理核心，提供可组合的入站、出站、路由、DNS 与传输层能力。

## 项目结构

```
xray-rs/
├── src/
│   ├── command/          # CLI 入口与启动编排
│   │   ├── root.rs       # 子命令解析
│   │   └── run.rs        # 主代理程序核心启动逻辑
│   ├── app/              # 配置装配为运行时抽象
│   │   ├── source.rs     # ConnectionSource (流量来源)
│   │   └── sink.rs       # ConnectionSink (流量去向)
│   ├── proxy/            # 协议实现层
│   │   ├── http.rs       # HTTP 协议
│   │   ├── socks.rs      # SOCKS 协议
│   │   ├── trojan.rs     # Trojan 协议
│   │   ├── vless.rs      # VLESS 协议
│   │   └── reverse.rs    # Reverse 协议
│   ├── route/            # 路由、DNS、规则匹配
│   │   ├── router.rs     # 主程序路由器
│   │   ├── resolver.rs   # DNS 解析器
│   │   ├── matcher.rs    # 域名/IP 匹配器
│   │   └── trie.rs       # 域名与 IP 规则索引
│   ├── transport/        # 底层传输抽象
│   │   ├── mod.rs        # TrStream 统一抽象
│   │   ├── tls.rs        # TLS 传输
│   │   ├── websocket.rs  # WebSocket 传输
│   │   └── grpc.rs       # gRPC 传输
│   ├── common/           # 通用类型与基础能力
│   ├── generated/        # 自动生成的 gRPC 代码
│   ├── main.rs           # 程序入口
│   └── lib.rs            # 库入口
│   └── build_info.rs     # 构建信息
├── src/bin/rsdns/        # 独立 DNS 程序
├── example/              # 示例配置文件
├── docs/                 # 架构与使用文档
├── tests/e2e/            # 端到端测试
├── proto/                # Protobuf 定义
├── Cargo.toml
└── Makefile
```

## 架构设计

### 核心抽象

| 抽象 | 职责 | 位置 |
|------|------|------|
| `ConnectionSource` | 流量从哪里来 (Listen/Daemon) | `app/source.rs` |
| `ConnectionSink` | 流量往哪里去 (Direct/Proxy/Block/Daemon) | `app/sink.rs` |
| `ProxyStream` | 桥梁对象，包含来源/目标/协议/标签/底层流 | `proxy/mod.rs` |
| `Router` | 将 ProxyStream 映射到 RoutingResult (primary_tag, fallback_tags) | `route/router.rs` |
| `DnsResolver` | DNS 解析 (hosts → 缓存 → 服务器 → 系统) | `route/resolver.rs` |
| `TrStream` | 统一传输流抽象 (Tcp/Tls/Udp/Grpc/WebSocket/Unix/Tun) | `transport/mod.rs` |

### 启动链路

```
main
  → root::execute()
    → Run::run()
      → 读取配置 (YAML/JSON)
      → 创建 Tokio runtime
      → run_proxy(config):
          1. 初始化 DnsResolver
          2. 构建 outbounds → ConnectionSink[]
          3. 构建 router (域名规则 → DomainMarisa, IP规则 → IpTrie)
          4. 构建 inbounds → ConnectionSource[]
          5. 启动路由与转发循环
```

### 数据流

```
配置文件 → app 装配 source/sink → inbound 生成 ProxyStream 
  → route 决策 outbound tag → sink 建立连接 → forwarder 双向转发
```

### 协议支持

**入站**: HTTP, SOCKS, Trojan, VLESS, Reverse  
**出站**: Freedom, Blackhole, SOCKS, Trojan, VLESS, Reverse  
**传输**: TCP, TLS, UDP, WebSocket, gRPC, Unix Socket, TUN  
**路由**: domain, ip, inboundTag, fallback

## 构建与运行

### 构建

```bash
cargo build --release
# 生成: target/release/xray-rs, target/release/rsdns
```

### Features

| Feature | 说明 |
|---------|------|
| `tun` | TUN 设备支持 (默认) |
| `mimalloc` | mimalloc 内存分配器 |
| `jemalloc` | jemalloc 内存分配器 (默认) |
| `aws-lc-rs` | AWS libcrypto (默认) |
| `ring` | ring 密码库 |

### 运行

```bash
# 主程序
./target/release/xray-rs run -c config.yaml

# 独立 DNS
cargo run --bin rsdns -- -c rsdns.yaml
```

## 配置格式

默认配置文件格式为 **YAML**，也支持 `.yaml`, `.yml`, `.json`。

### 最小配置示例

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

## 关键设计原则

1. **模块边界清晰**: CLI、装配、协议、路由、传输分层明确
2. **统一抽象**: ConnectionSource/ConnectionSink/ProxyStream 屏蔽协议细节
3. **路由与连接分离**: Router 只负责决策，不负责连接执行
4. **扩展点自然**: 新增协议放入 `proxy/`，新增传输放入 `transport/`

## 平台支持

- **Linux**: 推荐平台，有零拷贝转发优化 (libc::splice)
- **Android**: 部分转发优化路径与 Linux 共用
- **macOS/Unix**: 支持，但无 Linux 专属优化
- **Windows**: 理论上可构建，但 Unix Socket 不可用

## 测试

```bash
cargo test
```

## 重要注意事项

- Unix domain socket 仅在 `#[cfg(unix)]` 下可用
- StreamForwarder 在 linux/android 上有 splice 优化
- TUN 能力依赖 `tun` feature 与平台支持
- 版本命令 `version` 子命令当前基本为空实现
- rsdns 的监听目前主要实现了 UDP，tcp://, tls://, https:// 仍是 TODO
