# 使用说明

默认语言：中文 | [English](./usage.en.md)

本文基于当前 `src/` 的实现，说明如何使用 `xray-rs` 主程序，以及如何理解配置文件结构。README 以概览为主，本文件提供更细的用法说明。

## 1. 构建与运行

### 1.1 构建

```bash
cargo build --release
```

生成的常用二进制：

- `target/release/xray-rs`
- `target/release/rsdns`

### 1.2 运行主程序

主程序 CLI 来自：

- `src/main.rs`
- `src/command/root.rs`
- `src/command/run.rs`

当前主要子命令：

```bash
xray-rs run -c config.yaml
```

也支持 YAML：

```bash
xray-rs run -c config.yaml
xray-rs run -c config.yml
```

也支持 JSON：

```bash
xray-rs run -c config.json
```

默认配置文件名：

```bash
config.yaml
```

如果后缀既不是 `.json` 也不是 `.yaml/.yml`，当前实现会直接报错 `unsupported config format`。

## 2. 主程序启动时会做什么

`run` 命令内部会按以下顺序工作：

1. 读取配置文件并反序列化为 `Config`
2. 初始化 `DnsResolver`
3. 构建所有 outbounds，对每个 outbound 生成一个 `ConnectionSink`
4. 构建 `Router`
5. 构建并启动所有 inbounds，对每个 inbound 生成一个 `ConnectionSource`
6. 接收连接，生成 `ProxyStream`
7. 使用路由器选出目标 outbound tag
8. 若目标是代理型出站，尝试连接；若失败则尝试 fallback tags
9. 建立双向转发

对应源码主要位于：

- `src/command/run.rs`
- `src/app/mod.rs`
- `src/app/source.rs`
- `src/app/sink.rs`
- `src/route/router.rs`

## 3. 顶层配置结构

主配置结构定义在 `src/command/run.rs`：

```json
{
  "outbounds": [],
  "inbounds": [],
  "routing": {},
  "dns": {}
}
```

四个顶层字段都是可选的，但从实际使用角度看：

- 没有 `inbounds`，程序通常不会真正接收代理流量
- 没有 `outbounds`，即使有路由也可能没有有效目标
- 没有 `routing`，则会退化为“使用第一个 outbound 作为默认目标”
- 没有 `dns`，则使用默认 `DnsSettings`，并倾向于系统解析器

## 4. inbounds

入站配置定义在 `src/app/mod.rs` 的 `InboundSettings`：

```json
{
  "listen": "127.0.0.1",
  "port": 1080,
  "tag": "socks-in",
  "protocol": "socks",
  "settings": {},
  "streamSettings": {}
}
```

字段说明：

- `listen`：监听地址
- `port`：监听端口
- `tag`：入站标签，用于路由匹配 `inboundTag`
- `protocol`：协议类型
- `settings`：该协议自己的配置
- `streamSettings`：底层传输设置

### 4.1 当前支持的入站协议

根据 `src/proxy/mod.rs`：

- `http`
- `socks`
- `trojan`
- `vless`
- `reverse`
- `tun`（feature 打开时）

### 4.2 一个最小 socks 入站示例

```json
{
  "listen": "127.0.0.1",
  "port": 1080,
  "tag": "socks-in",
  "protocol": "socks"
}
```

`http` 与 `socks` 在当前实现中，如果没有显式提供 `settings`，会使用默认值；这在 `src/proxy/mod.rs` 的反序列化逻辑中有专门处理。

## 5. outbounds

出站配置定义在 `src/app/mod.rs` 的 `OutboundSettings`：

```json
{
  "tag": "direct",
  "protocol": "freedom",
  "settings": {},
  "streamSettings": {}
}
```

字段说明：

- `tag`：出站标签，供路由命中后引用
- `protocol`：出站协议
- `settings`：协议专属配置
- `streamSettings`：传输层配置

### 5.1 当前支持的出站协议

根据 `src/proxy/mod.rs`：

- `freedom`：直连
- `blackhole`：阻断/丢弃
- `socks`
- `trojan`
- `vless`
- `reverse`

### 5.2 最小出站示例

直连：

```json
{
  "tag": "direct",
  "protocol": "freedom"
}
```

阻断：

```json
{
  "tag": "block",
  "protocol": "blackhole"
}
```

## 6. routing

路由配置位于 `src/route/mod.rs`，主要结构如下：

```json
{
  "domainStrategy": "AsIs",
  "rules": [
    {
      "domain": ["example.com"],
      "ip": ["10.0.0.0/8"],
      "inboundTag": "socks-in",
      "outboundTag": "direct"
    }
  ],
  "fallback": {
    "tags": ["direct"]
  },
  "forwardIdleTimeout": 3600
}
```

### 6.1 domainStrategy

支持三个值：

- `AsIs`
- `IPIfNonMatch`
- `IPOnDemand`

行为概览：

- `AsIs`：优先按域名 trie 或 IP trie 直接匹配，不主动为域名解析 IP 再匹配
- `IPIfNonMatch`：域名规则未命中时，会尝试 DNS 解析，再用 IP 规则匹配
- `IPOnDemand`：可能更主动地拿目标 IP，再同时考虑域名和 IP 规则

详细路由逻辑可见 `src/route/router.rs`。

### 6.2 rules

每条规则可包含：

- `domain` / `domains`
- `ip` / `ips`
- `inboundTag`
- `outboundTag`

注意：

- 若规则没有 `domain`、`ip`、`inboundTag` 任一条件，当前实现会忽略该规则并记录警告
- `domain` 与 `ip` 均支持 `file:` 前缀，表示从文件读取规则列表

例如：

```json
{
  "domainStrategy": "IPIfNonMatch",
  "rules": [
    {
      "domain": ["example.com", "file:rules/domains.txt"],
      "outboundTag": "proxy"
    },
    {
      "ip": ["10.0.0.0/8", "file:rules/ips.txt"],
      "outboundTag": "direct"
    },
    {
      "inboundTag": "socks-in",
      "outboundTag": "proxy"
    }
  ]
}
```

### 6.3 fallback

`fallback.tags` 允许在主出站连接失败时按顺序尝试备用 tag。

在 `src/command/run.rs` 中，连接过程会：

1. 先尝试 `primary_tag`
2. 再依次尝试 `fallback_tags`
3. 一旦某个代理出站成功建立连接，就进入转发

## 7. dns

主程序 DNS 配置位于 `src/route/mod.rs` 和 `src/route/resolver.rs`。

示例：

```json
{
  "disableCache": false,
  "hosts": [
    "localhost:127.0.0.1",
    "file:///etc/hosts"
  ],
  "servers": [
    "1.1.1.1:53",
    "tcp://8.8.8.8:53",
    "https://dns.google/dns-query"
  ],
  "groups": []
}
```

### 7.1 hosts

`hosts` 支持两类写法：

1. 内联条目：
   - `domain:ip1,ip2`
2. 文件条目：
   - `file:///path/to/hosts`

### 7.2 servers

当前解析器支持：

- 普通 UDP：如 `1.1.1.1:53`
- TCP DNS：如 `tcp://8.8.8.8:53`
- 部分 DoH：如 `https://dns.google/dns-query`

当前实现中的限制：

- 自定义 DoH 服务器并非全部支持
- `tls://`（DoT）当前会返回不支持错误

### 7.3 cache

`disableCache = false` 时，当前 `DnsResolver` 使用固定 TTL 缓存；`true` 时禁用缓存。

## 8. streamSettings

`streamSettings` 来自 `src/transport/mod.rs`，主要包括：

```json
{
  "network": "tcp",
  "security": "none",
  "tlsSettings": {},
  "wsSettings": {},
  "grpcSettings": {},
  "sockopt": {}
}
```

当前可见能力：

- `network`
  - `tcp`
  - `ws`
  - `grpc`
- `security`
  - `none`
  - `tls`

这意味着代理协议本身与底层传输可以组合使用，例如 TCP/TLS、WS、gRPC 等。

## 9. 一个更完整的示例

```json
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 1080,
      "tag": "socks-in",
      "protocol": "socks"
    },
    {
      "listen": "127.0.0.1",
      "port": 8080,
      "tag": "http-in",
      "protocol": "http"
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": 1090
          }
        ]
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "inboundTag": "http-in",
        "outboundTag": "proxy"
      },
      {
        "domain": ["example.com"],
        "outboundTag": "direct"
      },
      {
        "ip": ["10.0.0.0/8"],
        "outboundTag": "block"
      }
    ],
    "fallback": {
      "tags": ["direct"]
    }
  },
  "dns": {
    "disableCache": false,
    "hosts": ["localhost:127.0.0.1"],
    "servers": ["1.1.1.1:53", "tcp://8.8.8.8:53"]
  }
}
```

> 注意：不同协议自己的 `settings` 细节由各协议模块决定。本文主要说明当前总装配与顶层结构，不穷举每个协议私有字段。

## 10. 日志与排障建议

当前主程序使用 `env_logger` 初始化日志，默认过滤级别是 `Info`。常见观察点：

- `Starting xray-rs proxy`
- DNS 初始化日志
- outbound 构建日志
- inbound 启动日志
- 路由结果日志
- daemon source/sink 退出日志

建议：

- 先用最小配置验证主流程
- 若路由未命中，检查 `tag` 与 `inboundTag` 是否一致
- 若域名路由不符合预期，检查 `domainStrategy`
- 若代理出站连接失败，检查是否配置了 `fallback.tags`

## 11. rsdns 简要使用

仓库内还包含独立 DNS 程序：

```bash
cargo run --bin rsdns -- -c rsdns.yaml
```

从 `src/bin/rsdns/main.rs` 可见：

- 默认配置文件：`rsdns.yaml`
- 支持 `listen`、`groups`、`upstreams`、`cache`、`hosts`、`rules`
- 规则动作包括：
  - `block`
  - `rewrite`
  - `forward`
- 当前监听实现主要是 `udp://`

如果你需要把 `rsdns` 作为项目主能力使用，建议另写更细的 DNS 专项文档。

## 12. 相关文档

- README（中文）：[`../README.md`](../README.md)
- README (English): [`../README.en.md`](../README.en.md)
- 架构说明（中文）：[`./arch.zh.md`](./arch.zh.md)
- Architecture (English): [`./arch.en.md`](./arch.en.md)

## 13. 说明

本文基于当前源码整理，重点描述“如何运行”和“配置如何被装配执行”。如果源码更新，请以实际实现为准。