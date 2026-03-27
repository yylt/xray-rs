# Architecture

Default language: English | [中文](./arch.zh.md)

This document explains the main architecture of `xray-rs`, the responsibilities of its modules, and the runtime flows of both the main program and `rsdns`, based on the current `src/` implementation.

## 1. Overview

From the current code structure, the project has two main runtime paths:

1. **Main proxy program**: reads config, builds inbounds, outbounds, routing, and DNS, then forwards connections
2. **Standalone DNS program `rsdns`**: reads YAML config, builds a rule engine, cache, and upstream DNS clients, and serves DNS requests

Overall, the main program acts like an “assembler + runtime coordinator”, while protocol details, routing logic, and transport abstractions are placed in separate modules.

## 2. Top-level module layout

According to `src/lib.rs` and the directory structure, the core modules are:

- `src/command/`
- `src/app/`
- `src/proxy/`
- `src/route/`
- `src/transport/`
- `src/common/`
- `src/bin/rsdns/`
- `src/generated/`

### 2.1 `command`

Responsibility: CLI entry and startup orchestration.

Key files:

- `src/main.rs`
- `src/command/root.rs`
- `src/command/run.rs`
- `src/command/version.rs`

Specifically:

- `src/main.rs` initializes logging and calls `root::execute()`
- `root.rs` parses subcommands
- `run.rs` contains the core startup logic for the main proxy program

### 2.2 `app`

Responsibility: assemble config objects into unified runtime abstractions.

Key transformations:

- `InboundSettings -> ConnectionSource`
- `OutboundSettings -> ConnectionSink`

The value of this layer is that upper layers do not need to care whether a concrete protocol is HTTP, SOCKS, Trojan, or VLESS. They only deal with “traffic sources” and “traffic sinks”.

### 2.3 `proxy`

Responsibility: protocol implementation layer.

According to `src/proxy/mod.rs`, it currently includes:

- `http`
- `socks`
- `trojan`
- `vless`
- `reverse`
- `tun` (when the feature is enabled)

This layer defines:

- `InboundSettings`
- `OutboundSettings`
- `Inbounder`
- `Outbounder`
- `ProxyStream`
- `StreamMetadata`

`ProxyStream` is the core runtime unit in the forwarding path:

- `metadata.src`
- `metadata.dst`
- `metadata.protocol`
- `metadata.inbound_tag`
- `inner`: the actual underlying stream object

### 2.4 `route`

Responsibility: name resolution, rule matching, and destination selection.

Main contents:

- `resolver.rs`: DNS resolver
- `router.rs`: router for the main proxy program
- `dns.rs`: DNS rule engine used by `rsdns`
- `matcher.rs`: matchers for domain/group and related logic
- `trie.rs`: index structures for domain and IP rules
- `cache.rs`: DNS cache-related functionality

`route` serves two distinct roles in the project:

1. **Main-program traffic routing**: choose an outbound tag for a connection
2. **Standalone DNS decision making**: choose an action for a DNS query, such as forward, block, or rewrite

### 2.5 `transport`

Responsibility: low-level transport abstraction and connection establishment.

This layer unifies different transport forms into `TrStream` and exposes support for:

- TCP
- TLS
- UDP
- WebSocket
- gRPC
- Unix sockets (platform-dependent)
- TUN-backed abstract streams

`StreamSettings` is also defined here, so protocol modules do not need to directly handle every low-level transport concern.

### 2.6 `common`

Responsibility: common types and foundational utilities.

This document does not enumerate everything there, but from the call graph it contains items such as:

- address abstraction `Address`
- protocol enum `Protocol`
- stream forwarder `StreamForwarder`
- parsing helpers and general networking utilities

### 2.7 `src/bin/rsdns`

Responsibility: standalone DNS executable.

Key files:

- `src/bin/rsdns/main.rs`
- `src/bin/rsdns/server.rs`
- `src/bin/rsdns/upstream.rs`

It does not go through the `command/run.rs` main proxy flow. Instead, it runs its own DNS-serving path.

## 3. Main program startup flow

After entering through `src/main.rs`, the main program follows roughly this path:

```text
main
  -> root::execute()
    -> Root::Run
      -> Run::run()
        -> read config
        -> create Tokio runtime
        -> run_proxy(config)
```

`run_proxy(config)` is the central assembly pipeline.

### 3.1 Step 1: initialize DNS

```text
Config.dns
  -> DnsSettings
  -> DnsResolver::new(...)
```

In the main program, the DNS resolver mainly serves two places:

1. **Routing phase**: when `domainStrategy` needs a domain resolved before IP-rule matching
2. **Direct-connection phase**: when `DirectSink` sees a domain destination and must resolve it before connecting

### 3.2 Step 2: build outbounds

Each `OutboundSettings` becomes a `ConnectionSink`:

- `Direct`
- `Proxy`
- `Block`
- `Daemon`

Typically:

- `freedom` becomes `DirectSink`
- `blackhole` becomes `Block`
- protocols like `socks/trojan/vless` become `ProxySink`
- background-oriented protocols like `reverse` become `DaemonSink`

If a sink is in daemon mode, `run_proxy` spawns a long-lived background task for it with `tokio::spawn`.

### 3.3 Step 3: build the router

`RoutingSettings::build_router()` will:

1. read `rules`
2. load domain rules into `DomainMarisaBuilder`
3. load IP rules into `IpTrieBuilder`
4. construct a `Router`
5. inject the DNS resolver
6. set fallback tags
7. add `inboundTag -> outboundTag` mapping rules

If the user does not provide `routing`, the program still constructs a basic `Router` and sets the first outbound tag as the default route.

### 3.4 Step 4: build inbounds

Each `InboundSettings` becomes a `ConnectionSource`:

- `Listen`
- `Daemon`

Typically:

- normal listening protocols become `ListenSource`
- background protocols become `DaemonSource`

For `ListenSource`:

- it first establishes a listener
- then continuously yields `ProxyStream`
- each `ProxyStream` is tagged with the corresponding `inbound_tag`

### 3.5 Step 5: route and forward

When an inbound connection arrives, the main path is:

```text
ListenSource
  -> ProxyStream
  -> Router::route(&stream)
  -> RoutingResult { primary_tag, fallback_tags }
  -> choose ConnectionSink
  -> connect or handle
  -> StreamForwarder::forward(...)
```

If the target sink is:

- `DirectSink`: connect directly to the destination
- `ProxySink`: connect via a proxy protocol
- `Block`: drop the connection
- `Daemon`: cannot handle a single stream directly

## 4. Key runtime abstractions

### 4.1 `ConnectionSource`

Defined in `src/app/source.rs`.

Represents “where traffic comes from” and is unified as:

- `ListenSource`
- `DaemonSource`

The upper layer only needs to know:

- whether it is daemon-style
- whether it can yield a `ProxyStream` stream
- whether it needs its own background task

### 4.2 `ConnectionSink`

Defined in `src/app/sink.rs`.

Represents “where traffic goes” and is unified as:

- `DirectSink`
- `ProxySink`
- `Block`
- `DaemonSink`

This lets `run_proxy` avoid understanding each protocol’s details and instead dispatch by sink category.

### 4.3 `ProxyStream`

Defined in `src/proxy/mod.rs`.

It is the bridge between the application layer and the protocol layer. A `ProxyStream` contains at least:

- source address
- destination address
- transport protocol (TCP/UDP)
- inbound tag
- actual underlying stream

This allows the router to make decisions based only on metadata without understanding protocol-specific internals.

## 5. Routing architecture

### 5.1 Responsibility of `Router`

The `Router` in `src/route/router.rs` maps a `ProxyStream` to a `RoutingResult`.

`RoutingResult` contains:

- `primary_tag`
- `fallback_tags`

So the router itself does not perform connections. It only makes the decision. Connection attempts and fallback retries are handled in `run_proxy`.

### 5.2 Routing priority

From the code, the effective priority is roughly:

1. `inbound_tag` rule match
2. domain/IP rule matching according to `domainStrategy`
3. default tag
4. if none exists, return `None`

### 5.3 Domain and IP rule indexes

In `src/route/mod.rs`:

- domain rules are compiled into `DomainMarisa`
- IP rules are compiled into `IpTrie`

The purpose is to transform config-time rule lists into data structures that are more efficient for runtime lookup, instead of re-scanning raw text rules on every request.

### 5.4 Fallback mechanism

Fallback is not a “backup default route”. It is a “retry alternate tags after the selected primary tag fails to connect”.

So it belongs to the **connection-stage fault-tolerance strategy**, not the rule-matching stage.

## 6. DNS architecture for the main program

Main-program DNS resolution is handled by `DnsResolver` in `src/route/resolver.rs`.

### 6.1 Resolution order

The current code roughly resolves in this order:

1. check `hosts`
2. check in-memory cache
3. if DNS servers are configured, query them through reusable resolver instances
4. otherwise fall back to the system resolver

### 6.2 Cache strategy

The current `DnsResolver` maintains a simple TTL cache:

- key: domain name
- value: list of IPs + expiry time

If `disableCache` is `true`, the TTL becomes 0, effectively disabling cache.

### 6.3 Protocol support

From the implementation, current support includes:

- UDP DNS
- TCP DNS
- some preset DoH cases

Explicitly incomplete or limited today:

- arbitrary custom DoH may not work
- DoT (`tls://`) is not yet supported

## 7. Difference between direct and proxy outbounds

### 7.1 `DirectSink`

`DirectSink` performs actual direct egress behavior:

1. if the target is a domain, resolve it through `DnsResolver`
2. establish a connection with `transport::Transport`
3. use standard bidirectional forwarding for TCP
4. use a dedicated recv/send loop for UDP

So `freedom` is not merely “let the stream pass through”; it actively opens the network connection to the destination.

### 7.2 `ProxySink`

`ProxySink` establishes a remote connection through `Outbounder` and a specific proxy protocol.

An important detail:

- it first calls `try_connect(dst, protocol)`
- only after the connection succeeds does it consume and forward the inbound stream

That is the foundation that makes fallback practical: if the preferred proxy tag fails to connect, another tag can still be tried without consuming the original inbound stream too early.

## 8. Transport architecture

`src/transport/mod.rs` unifies different underlying channels into `TrStream`, including:

- `Tcp`
- `TlsClient`
- `TlsServer`
- `Udp`
- `Grpc`
- `WebSocket*`
- `Unix`
- `Tun`
- `Buffered`

### 8.1 Why this matters

The benefit of this unified abstraction is:

- upper layers do not have to implement each low-level stream type separately
- the forwarder can operate on a single read/write abstraction
- transport enhancements such as TLS, WebSocket, and gRPC can be injected via `streamSettings` instead of being hardwired into every protocol implementation

### 8.2 `StreamSettings`

`StreamSettings` determines how a connection is established. Its core dimensions are currently:

- `network`
- `security`
- `sockopt`
- `tlsSettings`
- `wsSettings`
- `grpcSettings`

It effectively acts as the link-layer configuration below the proxy protocol layer.

## 9. `rsdns` architecture

`rsdns` shares some `route` capabilities with the main proxy program, but its runtime target is different: it processes DNS packets rather than proxy connection streams.

### 9.1 Startup flow

The flow in `src/bin/rsdns/main.rs` is roughly:

```text
main
  -> read rsdns.yaml
  -> build_groups
  -> build_hosts
  -> build_rules
  -> build_upstreams
  -> create DnsCache
  -> create RuleEngine
  -> create DnsServer
  -> start listeners from listen config
```

### 9.2 Core components

- `RuleEngine`: decides which action should be applied to a DNS query
- `HostsTable`: static hosts mapping
- `DnsCache`: DNS response cache
- `UpstreamClient`: sends queries to upstream DNS servers
- `DnsServer`: listens for and handles client DNS requests

### 9.3 Rule actions

In `src/route/dns.rs`, the visible actions are currently:

- `Forward { upstream, outbound_tag }`
- `Block`
- `Rewrite { ip }`
- `Hosts`

Among them:

- `Hosts` has the highest priority; if hosts matches, the result comes from hosts directly
- other rules are matched in declaration order
- if nothing matches, behavior falls back to a default `Forward`

### 9.4 groups and matchers

In `rsdns`, rules can combine:

- exact domain matching
- domain suffix matching
- group matching

A group can be loaded from a file or defined inline. It is then used by `RuleEngine` in a unified way.

## 10. Data-flow view

### 10.1 Main proxy program data flow

```text
config file
  -> command/run
  -> app assembles source/sink
  -> inbound yields ProxyStream
  -> route selects outbound tag
  -> sink establishes connection
  -> forwarder does bidirectional forwarding
```

### 10.2 `rsdns` data flow

```text
rsdns.yaml
  -> groups/hosts/rules/upstreams
  -> RuleEngine
  -> DnsServer receives query
  -> hosts / rule / default forward
  -> DNS response returned
```

## 11. Current architectural characteristics

### Strengths

- **Reasonably clear module boundaries**: CLI, assembly, protocols, routing, and transport are mostly separated
- **Clear runtime abstractions**: `ConnectionSource`, `ConnectionSink`, and `ProxyStream`
- **Natural extension points**: new protocols typically belong in `proxy/`, new transport forms in `transport/`
- **Routing separated from connection execution**: the router decides, while runtime code executes

### Current limitations or caveats

- full field-level documentation for all protocol-specific config is still to be extracted from individual protocol modules
- the `version` subcommand is currently almost empty
- `rsdns` listening is mainly implemented for UDP; `tcp://`, `tls://`, and `https://` remain TODOs
- some capabilities depend on features or dependency-version constraints, such as `tun` and the exact DoT/DoH support range

## 12. Recommended source-reading order

If you want to continue reading the source, a good order is:

1. `src/main.rs`
2. `src/command/root.rs`
3. `src/command/run.rs`
4. `src/app/mod.rs`
5. `src/app/source.rs` / `src/app/sink.rs`
6. `src/proxy/mod.rs`
7. `src/route/mod.rs` / `src/route/router.rs` / `src/route/resolver.rs`
8. `src/transport/mod.rs`
9. `src/bin/rsdns/main.rs`

This makes it easier to understand the main flow first, then dive into implementation details.

## 13. Related docs

- README (Chinese): [`../README.md`](../README.md)
- README (English): [`../README.en.md`](../README.en.md)
- Usage Guide (Chinese): [`./usage.zh.md`](./usage.zh.md)
- Usage Guide (English): [`./usage.en.md`](./usage.en.md)

## 14. Notes

This is an architecture description of the current implementation, not a future roadmap. If module responsibilities or startup flows change later, the documentation should be updated to match the source.
