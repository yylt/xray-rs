# xray-rs

默认语言：中文 | [English](./README.en.md)

一个使用 Rust 实现的轻量代理核心，提供可组合的入站、出站、路由、DNS 与传输层能力。

## 特性

- 入站：`http`、`socks`、`trojan`、`vless`、`reverse`
- 出站：`freedom`、`blackhole`、`socks`、`trojan`、`vless`、`reverse`
- 路由：支持 `domain`、`ip`、`inboundTag` 与 fallback
- 传输：支持 `tcp`、`ws`、`grpc`，并支持 `tls`
- DNS：内置 `DnsResolver`，并提供独立二进制 `rsdns`

## 快速开始

### 构建

```bash
cargo build --release
```

生成：

- `target/release/xray-rs`
- `target/release/rsdns`

### 运行主程序

默认配置文件格式为 **YAML**：

```bash
cargo run -- run -c config.yaml
# 或
./target/release/xray-rs run -c config.yaml
```

`run` 命令当前默认配置文件名为：

```bash
config.yaml
```

也支持：

- `.yaml`
- `.yml`
- `.json`

## 最小配置示例

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

## example 目录说明

仓库中的 `example/` 目录提供了可直接参考的示例配置：

- `example/config.yaml`：综合示例，包含 `http` / `socks` 入站、`trojan` / `vless` 出站、路由与 DNS 基本写法
- `example/example-server.yaml`：TCP + Trojan 服务端
- `example/example-client.yaml`：TCP + Trojan 客户端（本地 HTTP / SOCKS 入站）
- `example/example-grpc-server.yaml`：gRPC + Trojan 服务端
- `example/example-grpc-client.yaml`：gRPC + Trojan 客户端
- `example/example-grpc-tls-server.yaml`：gRPC + TLS + Trojan 服务端
- `example/example-grpc-tls-client.yaml`：gRPC + TLS + Trojan 客户端
- `example/example-ws-server.yaml`：WebSocket + Trojan 服务端
- `example/example-ws-client.yaml`：WebSocket + Trojan 客户端
- `example/example-lb-client.yaml`：多上游与 fallback 示例，可用于当前 e2e 的负载切换场景
- `example/dns_config.json`：DNS 与基于文件域名规则的路由示例

### 运行示例

例如运行 gRPC + Trojan 场景：

```bash
./target/release/xray-rs run -c example/example-grpc-server.yaml
./target/release/xray-rs run -c example/example-grpc-client.yaml
```

例如运行 gRPC + TLS + Trojan 场景：

```bash
./target/release/xray-rs run -c example/example-grpc-tls-server.yaml
./target/release/xray-rs run -c example/example-grpc-tls-client.yaml
```

> 说明：`example/dns_config.json` 依赖 `tests/e2e/testdata/ads.txt` 与 `tests/e2e/testdata/cn.txt`。在 e2e 场景中这些文件会由测试代码自动创建。

## 支持的平台

基于当前源码可见信息：

### OS

- **Linux**：推荐平台；存在针对 `linux/android` 的零拷贝转发优化
- **Android**：部分转发优化路径与 Linux 共用
- **macOS / 其他 Unix-like**：具备 Unix Socket 相关支持，但不走 Linux 专属优化路径
- **Windows**：主程序理论上可构建部分能力，但 Unix Socket 不可用；`tun` 与部分底层行为需按实际编译结果验证

### 平台相关说明

- `Unix domain socket` 仅在 `#[cfg(unix)]` 下可用
- `StreamForwarder` 在 `linux/android` 上有 `libc::splice` 优化
- `tun` 能力依赖 `tun` feature 与目标平台支持

## 文档

- 使用说明（中文）：[`docs/usage.zh.md`](./docs/usage.zh.md)
- Usage Guide (English): [`docs/usage.en.md`](./docs/usage.en.md)
- 架构说明（中文）：[`docs/arch.zh.md`](./docs/arch.zh.md)
- Architecture (English): [`docs/arch.en.md`](./docs/arch.en.md)

## rsdns

仓库同时包含独立 DNS 程序：

```bash
cargo run --bin rsdns -- -c rsdns.yaml
```

当前从源码可见：

- 默认配置文件：`rsdns.yaml`
- 支持 `forward`、`block`、`rewrite`
- 当前监听实现主要是 `udp://`

## 开发

```bash
cargo test
```

常见 feature：

- `tun`
- `mimalloc`
- `jemalloc`
- `aws-lc-rs`
- `ring`

## 说明

文档内容基于当前 `src` 实现整理；若实现变化，请以源码为准。
