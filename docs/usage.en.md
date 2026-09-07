# Usage Guide

Default language: English | [中文](./usage.zh.md)

This document is based on the current `src/` implementation and explains how to use the main `xray-rs` program and how to understand its configuration structure. The README is a high-level overview; this file provides more detailed usage notes.

## 1. Build and Run

### 1.1 Build

```bash
cargo build --release
```

Common binaries produced:

- `target/release/xray-rs`

### 1.2 Run the main program

The main CLI is defined by:

- `src/main.rs`
- `src/command/root.rs`
- `src/command/run.rs`

The primary subcommand is:

```bash
xray-rs run -c config.yaml
```

YAML is also supported:

```bash
xray-rs run -c config.yaml
xray-rs run -c config.yml
```

JSON is also supported:

```bash
xray-rs run -c config.json
```

Default config filename:

```bash
config.yaml
```

The `run` subcommand accepts a tokio runtime thread-mode option, default `single`:

```bash
xray-rs run -c config.yaml --thread single
xray-rs run -c config.yaml --thread multi
```

- `single`: current-thread runtime (`new_current_thread`)
- `multi`: multi-thread runtime (`new_multi_thread`)

If the file extension is neither `.json` nor `.yaml/.yml`, the current implementation returns `unsupported config format`.

## 2. What happens at startup

Internally, the `run` command works in this order:

1. Read the config file into `Config`
2. Initialize `DnsResolver`
3. Build all outbounds and turn each into a `ConnectionSink`
4. Build the `Router`
5. Build and start all inbounds and turn each into a `ConnectionSource`
6. Accept incoming connections and wrap them as `ProxyStream`
7. Use the router to select the outbound tag
8. If the selected outbound is proxy-based, attempt connection and retry fallback tags on failure
9. Start bidirectional forwarding

Relevant source locations:

- `src/command/run.rs`
- `src/app/mod.rs`
- `src/app/source.rs`
- `src/app/sink.rs`
- `src/route/router.rs`

## 3. Top-level config structure

The main config struct is defined in `src/command/run.rs`:

```json
{
  "outbounds": [],
  "inbounds": [],
  "routing": {},
  "dns": {},
  "log": {}
}
```

All five top-level fields are optional, but in practical terms:

- without `inbounds`, the program usually will not receive proxy traffic
- without `outbounds`, routing may not have any useful target
- without `routing`, behavior falls back to using the first outbound as the default target
- without `dns`, the program uses default `DnsSettings` and tends to rely on the system resolver
- without `log`, logs go to stderr at info level

The `log` field structure:

```json
{
  "file": "/var/log/xray-rs.log",
  "level": "info"
}
```

- `file`: path of the log file (append mode); when omitted, logs go to stderr
- `level`: filter level `off|error|warn|info|debug|trace`, default `info`

The matching config struct `LogSettings` lives in `src/common/rslog.rs`; the main config struct is in `src/command/run.rs`.

## 4. inbounds

Inbound config is defined by `InboundSettings` in `src/app/mod.rs`:

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

Field meanings:

- `listen`: listen address
- `port`: listen port
- `tag`: inbound tag used by routing `inboundTag`
- `protocol`: inbound protocol type
- `settings`: protocol-specific config
- `streamSettings`: transport-layer settings

### 4.1 Supported inbound protocols

According to `src/proxy/mod.rs`:

- `http`
- `socks`
- `trojan`
- `vless`
- `reverse`
- `tun` (when the feature is enabled)

### 4.2 Minimal socks inbound example

```json
{
  "listen": "127.0.0.1",
  "port": 1080,
  "tag": "socks-in",
  "protocol": "socks"
}
```

In the current implementation, `http` and `socks` can use defaults if `settings` is omitted. This is handled explicitly in the deserialization logic in `src/proxy/mod.rs`.

## 5. outbounds

Outbound config is defined by `OutboundSettings` in `src/app/mod.rs`:

```json
{
  "tag": "direct",
  "protocol": "freedom",
  "settings": {},
  "streamSettings": {}
}
```

Field meanings:

- `tag`: outbound tag referenced by routing
- `protocol`: outbound protocol
- `settings`: protocol-specific config
- `streamSettings`: transport-layer settings

### 5.1 Supported outbound protocols

According to `src/proxy/mod.rs`:

- `freedom`: direct connection
- `blackhole`: block/drop traffic
- `socks`
- `trojan`
- `vless`
- `reverse`

### 5.2 Minimal outbound examples

Direct:

```json
{
  "tag": "direct",
  "protocol": "freedom"
}
```

Blackhole:

```json
{
  "tag": "block",
  "protocol": "blackhole"
}
```

## 6. routing

Routing config is defined in `src/route/mod.rs` and looks roughly like this:

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

Supported values:

- `AsIs`
- `IPIfNonMatch`
- `IPOnDemand`

Behavior summary:

- `AsIs`: match directly against the domain trie or IP trie, without proactively resolving domains for IP matching
- `IPIfNonMatch`: if domain matching fails, try DNS resolution and then match IP rules
- `IPOnDemand`: may resolve IPs more proactively and consider both domain and IP rules

See `src/route/router.rs` for the detailed routing behavior.

### 6.2 rules

Each rule may contain:

- `domain` / `domains`
- `ip` / `ips`
- `inboundTag`
- `outboundTag`

Notes:

- if a rule has none of `domain`, `ip`, or `inboundTag`, the current implementation ignores it and logs a warning
- both `domain` and `ip` support a `file:` prefix to load entries from files

Example:

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

`fallback.tags` allows retrying alternate tags when the primary outbound connection fails.

In `src/command/run.rs`, connection handling does this:

1. try `primary_tag`
2. then try each `fallback_tag` in order
3. once a proxy outbound connects successfully, start forwarding

## 7. dns

Main-program DNS config is defined in `src/route/mod.rs` and `src/route/resolver.rs`.

Example:

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

`hosts` supports two formats:

1. inline entries:
   - `domain:ip1,ip2`
2. file entries:
   - `file:///path/to/hosts`

### 7.2 servers

The current resolver supports:

- plain UDP, such as `1.1.1.1:53`
- TCP DNS, such as `tcp://8.8.8.8:53`
- some DoH endpoints, such as `https://dns.google/dns-query`

Current limitations in the implementation:

- not every custom DoH server is supported
- `tls://` (DoT) currently returns an unsupported error

### 7.3 cache

When `disableCache = false`, the current `DnsResolver` uses a fixed-TTL cache. When `true`, caching is disabled.

## 8. streamSettings

`streamSettings` comes from `src/transport/mod.rs` and mainly includes:

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

Visible capabilities:

- `network`
  - `tcp`
  - `ws`
  - `grpc`
- `security`
  - `none`
  - `tls`

This means protocol logic can be combined with different transport layers such as TCP/TLS, WebSocket, or gRPC.

## 9. A fuller example

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

> Note: the exact `settings` structure for each protocol is defined by the protocol modules themselves. This document focuses on the top-level assembly and runtime behavior rather than every protocol-specific field.

## 10. Logging and troubleshooting

The main program currently initializes logging with slog (via `src/common/rslog.rs`). Logging behavior is configured through the top-level `log` field:

- without `log.file`: logs go to stderr
- with `log.file`: logs are appended to the given file
- `log.level` controls the filter level, default `info`

Common things to watch for:

- `Starting xray-rs proxy`
- DNS initialization logs
- outbound build logs
- inbound startup logs
- routing result logs
- daemon source/sink exit logs

Suggestions:

- start with a minimal config to validate the main path
- if routing does not match, verify that `tag` and `inboundTag` align
- if domain routing behaves unexpectedly, check `domainStrategy`
- if proxy outbound connections fail, check whether `fallback.tags` is configured

## 11. `rsdns`

The standalone DNS program `rsdns` has moved to its own repository (the `rsdns/` directory in this repo is an independent crate). See that repository's README and `docs/design/` for usage and design documentation.

## 12. Related docs

- README (Chinese): [`../README.md`](../README.md)
- README (English): [`../README.en.md`](../README.en.md)
- Architecture (Chinese): [`./arch.zh.md`](./arch.zh.md)
- Architecture (English): [`./arch.en.md`](./arch.en.md)

## 13. Notes

This document is derived from the current source code and focuses on how to run the program and how config is assembled into runtime behavior. If the implementation changes, treat the source code as the authority.
