# 架构说明

默认语言：中文 | [English](./arch.en.md)

本文基于当前 `src/` 源码，说明 `xray-rs` 的主要架构、模块职责，以及主程序与 `rsdns` 的运行链路。

## 1. 总览

从当前代码结构看，项目可以分成两条主要运行线：

1. **主代理程序**：读取配置，构建入站、出站、路由与 DNS，然后进行连接转发
2. **独立 DNS 程序 `rsdns`**：读取 YAML 配置，构建规则引擎、缓存与上游 DNS，提供规则驱动的 DNS 服务

整体上，主程序更像一个“装配器 + 运行时协调器”，而协议细节、路由逻辑、传输抽象分别放在独立模块中。

## 2. 顶层模块划分

根据 `src/lib.rs` 与目录结构，核心模块包括：

- `src/command/`
- `src/app/`
- `src/proxy/`
- `src/route/`
- `src/transport/`
- `src/common/`
- `src/bin/rsdns/`
- `src/generated/`

### 2.1 `command`

职责：CLI 入口与启动编排。

关键文件：

- `src/main.rs`
- `src/command/root.rs`
- `src/command/run.rs`
- `src/command/version.rs`

其中：

- `src/main.rs` 初始化日志并调用 `root::execute()`
- `root.rs` 负责解析子命令
- `run.rs` 是主代理程序的核心启动逻辑

### 2.2 `app`

职责：把配置对象装配成统一的运行时抽象。

关键抽象：

- `InboundSettings -> ConnectionSource`
- `OutboundSettings -> ConnectionSink`

这层的价值在于：上层不需要关心具体协议是 HTTP、SOCKS、Trojan 还是 VLESS，只需要把它们视为“流量来源”与“流量去向”。

### 2.3 `proxy`

职责：协议实现层。

根据 `src/proxy/mod.rs`，当前包含：

- `http`
- `socks`
- `trojan`
- `vless`
- `reverse`
- `tun`（feature 打开时）

这一层定义了：

- `InboundSettings`
- `OutboundSettings`
- `Inbounder`
- `Outbounder`
- `ProxyStream`
- `StreamMetadata`

`ProxyStream` 是整个转发链路中的核心数据单元：

- `metadata.src`
- `metadata.dst`
- `metadata.protocol`
- `metadata.inbound_tag`
- `inner`：真实的底层流对象

### 2.4 `route`

职责：名称解析、规则匹配、目标决策。

主要内容：

- `resolver.rs`：DNS 解析器
- `router.rs`：主代理程序的路由器
- `dns.rs`：`rsdns` 使用的 DNS 规则引擎
- `matcher.rs`：域名/组等匹配器
- `trie.rs`：域名与 IP 规则索引结构
- `cache.rs`：DNS 缓存相关能力

`route` 在项目中承担两类职责：

1. **主程序流量路由**：给连接选一个 outbound tag
2. **独立 DNS 决策**：给 DNS 查询选一个动作，如转发、阻断、重写

### 2.5 `transport`

职责：底层传输抽象与连接建立。

这一层把不同传输方式统一成 `TrStream`，并对外提供：

- TCP
- TLS
- UDP
- WebSocket
- gRPC
- Unix Socket（平台相关）
- TUN 抽象流

`StreamSettings` 也是在这一层定义，因此协议模块不必直接处理所有底层传输细节。

### 2.6 `common`

职责：通用类型与基础能力。

虽然本文不逐项展开，但从调用关系看，这里包含：

- 地址抽象 `Address`
- 协议枚举 `Protocol`
- 数据转发器 `StreamForwarder`
- 解析辅助与网络公共逻辑

### 2.7 `src/bin/rsdns`

职责：独立 DNS 可执行程序。

关键文件：

- `src/bin/rsdns/main.rs`
- `src/bin/rsdns/server.rs`
- `src/bin/rsdns/upstream.rs`

它不走 `command/run.rs` 那套代理主流程，而是单独完成 DNS 规则服务。

## 3. 主程序启动链路

主程序从 `src/main.rs` 进入后，大致链路如下：

```text
main
  -> root::execute()
    -> Root::Run
      -> Run::run()
        -> 读取配置
        -> 创建 Tokio runtime
        -> run_proxy(config)
```

`run_proxy(config)` 是核心装配流程。

### 3.1 第一步：初始化 DNS

```text
Config.dns
  -> DnsSettings
  -> DnsResolver::new(...)
```

DNS 解析器在主程序中主要服务两处：

1. **路由阶段**：当 `domainStrategy` 需要域名解析后再匹配 IP 规则
2. **直连阶段**：`DirectSink` 遇到域名目标时，需要把域名解析成 IP 再连接

### 3.2 第二步：构建 outbounds

每个 `OutboundSettings` 最终会变成一个 `ConnectionSink`：

- `Direct`
- `Proxy`
- `Block`
- `Daemon`

其中：

- `freedom` 通常变成 `DirectSink`
- `blackhole` 变成 `Block`
- `socks/trojan/vless` 这类通常变成 `ProxySink`
- `reverse` 这类后台型协议会变成 `DaemonSink`

如果 sink 是 daemon 模式，`run_proxy` 会单独 `tokio::spawn` 一个后台任务长期运行。

### 3.3 第三步：构建 router

`RoutingSettings::build_router()` 会：

1. 读取 `rules`
2. 将域名规则装入 `DomainMarisaBuilder`
3. 将 IP 规则装入 `IpTrieBuilder`
4. 构造 `Router`
5. 注入 DNS 解析器
6. 设置 fallback tags
7. 添加 `inboundTag -> outboundTag` 的映射规则

如果用户没有提供 `routing`，则仍会构造一个基础 `Router`，并把第一个 outbound tag 设为默认出站。

### 3.4 第四步：构建 inbounds

每个 `InboundSettings` 最终会变成一个 `ConnectionSource`：

- `Listen`
- `Daemon`

其中：

- 普通监听型协议生成 `ListenSource`
- 后台型协议生成 `DaemonSource`

对于 `ListenSource`：

- 先建立监听
- 后续持续产出 `ProxyStream`
- 每条 `ProxyStream` 会被附加上对应的 `inbound_tag`

### 3.5 第五步：路由与转发

当一个入站连接进入后，主流程为：

```text
ListenSource
  -> ProxyStream
  -> Router::route(&stream)
  -> RoutingResult { primary_tag, fallback_tags }
  -> 选择 ConnectionSink
  -> 建连或处理
  -> StreamForwarder::forward(...)
```

若目标 sink 是：

- `DirectSink`：直接连接远端
- `ProxySink`：经代理协议连接远端
- `Block`：直接丢弃连接
- `Daemon`：不能直接处理单条流

## 4. 关键运行时抽象

### 4.1 `ConnectionSource`

定义于 `src/app/source.rs`。

代表“流量从哪里来”，统一封装为：

- `ListenSource`
- `DaemonSource`

对上层来说，只需要知道：

- 是否 daemon
- 是否可以产出 `ProxyStream` 流
- 是否需要独立后台运行

### 4.2 `ConnectionSink`

定义于 `src/app/sink.rs`。

代表“流量往哪里去”，统一封装为：

- `DirectSink`
- `ProxySink`
- `Block`
- `DaemonSink`

这种设计让 `run_proxy` 不需要感知每种协议的细节，只需要按 sink 类型采取不同调度策略。

### 4.3 `ProxyStream`

定义于 `src/proxy/mod.rs`。

它是应用层与协议层之间的桥梁。一个 `ProxyStream` 至少包含：

- 来源地址
- 目标地址
- 传输协议（TCP/UDP）
- 所属入站标签
- 实际底层流

这让路由器可以仅依赖元数据进行决策，而不用理解具体代理协议内部实现。

## 5. 路由架构

### 5.1 Router 的职责

`src/route/router.rs` 中的 `Router` 负责把一个 `ProxyStream` 映射到一个 `RoutingResult`。

`RoutingResult` 包含：

- `primary_tag`
- `fallback_tags`

这说明路由器本身并不直接负责连接，只负责“决策”。连接尝试与 fallback 重试发生在 `run_proxy` 中。

### 5.2 路由优先级

从代码可见，优先级大致是：

1. `inbound_tag` 命中规则
2. 按 `domainStrategy` 进行域名/IP 规则匹配
3. 默认 tag
4. 若都没有，则返回 `None`

### 5.3 域名与 IP 规则索引

在 `src/route/mod.rs` 中：

- 域名规则构建为 `DomainMarisa`
- IP 规则构建为 `IpTrie`

这样做的目的，是把“配置文件中的规则列表”在启动时编译为更适合运行时查找的数据结构，而不是每次请求都顺序遍历原始文本规则。

### 5.4 fallback 机制

fallback 机制不是“备用默认路由”，而是“主路由标签已选定后，若连接失败时再依次尝试其他标签”。

因此它属于**连接阶段的容错策略**，而不是规则匹配阶段的策略。

## 6. DNS 架构（主程序）

主程序 DNS 解析由 `src/route/resolver.rs` 中的 `DnsResolver` 负责。

### 6.1 解析顺序

当前代码中的解析顺序大致是：

1. 先查 `hosts`
2. 再查内存缓存
3. 若配置了 DNS servers，则并发/复用 resolver 查询
4. 若未配置或查询链路不命中，则退回系统解析器

### 6.2 缓存策略

当前 `DnsResolver` 内部维护一个简单 TTL 缓存：

- key：域名
- value：IP 列表 + 过期时间

若 `disableCache` 为 `true`，TTL 会被置为 0，相当于关闭缓存。

### 6.3 协议支持情况

从实现看，当前支持：

- UDP DNS
- TCP DNS
- 部分预设 DoH

当前明确未完成或有限制：

- 自定义 DoH 不一定可用
- DoT (`tls://`) 暂未支持

## 7. 直连与代理出站的差异

### 7.1 `DirectSink`

`DirectSink` 负责真正的“直连”行为：

1. 若目标是域名，先调用 `DnsResolver`
2. 通过 `transport::Transport` 建立连接
3. TCP 走标准双向转发
4. UDP 走专门的收发循环

因此，`freedom` 的实现并不是简单地把流“原样放行”，而是会真正发起到目标地址的网络连接。

### 7.2 `ProxySink`

`ProxySink` 则通过 `Outbounder` 建立“经过某种代理协议的远端连接”。

一个重要点是：

- 它先 `try_connect(dst, protocol)`
- 只有连接成功后，才消费并转发 inbound stream

这正是 fallback 能够工作的基础：如果首选代理 tag 建连失败，仍可以尝试下一条 tag，而不会过早消耗原始连接流。

## 8. 传输层架构

`src/transport/mod.rs` 将不同底层通道统一为 `TrStream`，包括：

- `Tcp`
- `TlsClient`
- `TlsServer`
- `Udp`
- `Grpc`
- `WebSocket*`
- `Unix`
- `Tun`
- `Buffered`

### 8.1 设计意义

这层统一抽象的意义在于：

- 上层协议不必分别处理每种底层流类型
- 转发器只需要面对一个统一可读写的流对象
- 传输增强能力（如 TLS、WebSocket、gRPC）可以通过 `streamSettings` 注入，而非耦合进每个协议模块

### 8.2 `StreamSettings`

`StreamSettings` 决定连接如何建立，当前核心维度是：

- `network`
- `security`
- `sockopt`
- `tlsSettings`
- `wsSettings`
- `grpcSettings`

它相当于“协议之下的链路配置层”。

## 9. `rsdns` 架构

`rsdns` 与主代理程序共享一部分 `route` 能力，但它的运行目标不同：它处理的是 DNS 查询报文，而不是代理连接流。

### 9.1 启动流程

`src/bin/rsdns/main.rs` 的流程大致为：

```text
main
  -> 读取 rsdns.yaml
  -> build_groups
  -> build_hosts
  -> build_rules
  -> build_upstreams
  -> 创建 DnsCache
  -> 创建 RuleEngine
  -> 创建 DnsServer
  -> 按 listen 启动监听
```

### 9.2 核心组件

- `RuleEngine`：判断 DNS 查询应执行什么动作
- `HostsTable`：静态 hosts 映射
- `DnsCache`：DNS 响应缓存
- `UpstreamClient`：对上游 DNS 发起查询
- `DnsServer`：监听并处理客户端 DNS 请求

### 9.3 规则动作

`src/route/dns.rs` 当前可见的动作有：

- `Forward { upstream, outbound_tag }`
- `Block`
- `Rewrite { ip }`
- `Hosts`

其中：

- `Hosts` 优先级最高，只要 hosts 命中就直接返回 hosts 结果
- 其余规则按声明顺序匹配
- 若都不命中，则回退到默认 `Forward`

### 9.4 groups 与 matcher

`rsdns` 中的 rules 可以结合：

- 域名精确匹配
- 域名后缀匹配
- group 匹配

group 可以从文件加载，也可以 inline 定义。最终统一进入 `RuleEngine` 使用。

## 10. 数据流视角

### 10.1 主代理程序数据流

```text
配置文件
  -> command/run
  -> app 装配 source/sink
  -> inbound 生成 ProxyStream
  -> route 决策 outbound tag
  -> sink 建立连接
  -> forwarder 双向转发
```

### 10.2 rsdns 数据流

```text
rsdns.yaml
  -> groups/hosts/rules/upstreams
  -> RuleEngine
  -> DnsServer 接收查询
  -> 命中 hosts / rule / default forward
  -> 返回 DNS 响应
```

## 11. 当前架构特点

### 优点

- **模块边界较清晰**：CLI、装配、协议、路由、传输基本分层
- **统一抽象较明确**：`ConnectionSource` / `ConnectionSink` / `ProxyStream`
- **扩展点自然**：新增协议通常放入 `proxy/`，新增传输通常放入 `transport/`
- **路由与连接分离**：Router 只负责决策，不负责连接执行

### 当前限制或注意点

- 一些配置字段的完整文档仍需进一步从协议模块中提炼
- `version` 子命令当前基本为空实现
- `rsdns` 的监听目前主要实现了 UDP，`tcp://`、`tls://`、`https://` 仍是 TODO
- 某些底层实现能力存在 feature 或依赖版本限制，例如 `tun`、DoT/DoH 支持范围

## 12. 适合理解源码的阅读顺序

如果你准备继续读源码，推荐顺序如下：

1. `src/main.rs`
2. `src/command/root.rs`
3. `src/command/run.rs`
4. `src/app/mod.rs`
5. `src/app/source.rs` / `src/app/sink.rs`
6. `src/proxy/mod.rs`
7. `src/route/mod.rs` / `src/route/router.rs` / `src/route/resolver.rs`
8. `src/transport/mod.rs`
9. `src/bin/rsdns/main.rs`

这样最容易先理解“主流程”，再深入到“具体实现”。

## 13. 相关文档

- README（中文）：[`../README.md`](../README.md)
- README (English): [`../README.en.md`](../README.en.md)
- 使用说明（中文）：[`./usage.zh.md`](./usage.zh.md)
- Usage Guide (English): [`./usage.en.md`](./usage.en.md)

## 14. 说明

本文是面向当前实现的架构说明，不是未来规划文档。若后续模块职责或启动流程发生变化，请以源码为准同步更新。