# xray-rs

默认语言：中文 | [English](./README.en.md)

一个使用 Rust 实现的轻量代理核心，提供可组合的入站、出站、路由、DNS 与传输层能力。

## 特性

- 入站：`http`、`socks`、`trojan`、`vless`、`reverse`
- 出站：`freedom`、`blackhole`、`socks`、`trojan`、`vless`、`reverse`
- 路由：支持 `domain`、`ip`、`inboundTag` 与 fallback
- 传输：支持 `tcp`、`ws`、`grpc`，并支持 `tls`
- DNS：内置 `DnsResolver`（独立 DNS 程序 `rsdns` 已迁移至独立仓库）

## XHTTP 直连与 Caddy 反代

直连配置：[server](example/example-xhttp-server.yaml) / [client](example/example-xhttp-client.yaml)。
客户端在 `127.0.0.1:2080` 提供 HTTP 代理，服务端监听 `127.0.0.1:20080`。

Caddy TLS 入口配置：[Caddyfile](example/Caddyfile.xhttp) / [client](example/example-xhttp-caddy-client.yaml)。
将两份配置中的 `proxy.example.net` 替换为自己的域名；服务端继续使用上述无 TLS 配置。
Caddy 终止 TLS 并通过 h2c 转发，保留 `/test/*` 路径（不要使用会剥离前缀的 `handle_path`）。
客户端上传/下载的显式 `address` 同时用于 DNS、TLS SNI/证书校验与 HTTP 虚拟主机路由，`alpn` 设置为 `[h2]`。
端点块中省略 `address` 时，先回落到 TLS 的 `serverName`，再回落到 outbound 地址；`port` 仍必填。
显式 IP 不再被全局 `serverName` 覆盖：使用 IP 证书校验，且不发送域名 SNI。
仅支持 `packet-up`（默认）；`stream-one` 与 `stream-up` 已移除，旧配置须删除 `mode` 或改为 `packet-up`。
`packet-up` 使用定长 POST 上传与 GET 下载，适合存在请求缓冲的链路。

XHTTP 出站支持 `xhttpSettings.loadBalancer: least_connection`（默认），
也可设置 `round_robin` 或 `least_loaded`。域名全部 IPv4/IPv6 参与选址，每个 IP 复用 HTTP/2 连接，
并发首次连接合并建连；DNS 在新请求时按需刷新，快照间隔 300 秒，无后台轮询。
整个 upload 省略时，地址先取 TLS `serverName`，否则取 outbound 地址；端口沿用 outbound，不自动猜测 443。
整个 download 省略时继承已解析的 upload。
同一入口的 POST/GET 固定同一 IP，共用该 IP 的连接池。每次 GET/POST 根据对端
`SETTINGS_MAX_CONCURRENT_STREAMS` 选择有容量的连接；已有连接全部满载时，向选定 IP
新建连接，不在已知满载的连接上排队。无须配置本地并发上限，空闲连接暂不回收。
首次连接等待协议初始化（含 SETTINGS），对端宣告零容量时返回错误，避免反复扩建连接。
对端动态降低上限时，已接纳但尚未发出的请求仍可能由 HTTP/2 协议层暂缓；新请求使用更新后的上限。
`xhttpSettings.http2InitialWindowSize` 配置 HTTP/2 单流初始流控窗口（字节，默认 4 MiB，
有效范围 1..2147483647），客户端与服务端各自生效：客户端该值决定下载方向允许的在途数据量，
服务端该值约束上传方向；连接级窗口固定取该值的 2 倍。低于或高于请按链路 BDP 调整，
调大只增内存、不增加延迟。
如果 Caddy 内部再均衡到多个独立 XHTTP server，必须按会话 UUID 保持 POST/GET 路由一致；
客户端选中同一 Caddy IP 并不能保证 Caddy 选中同一后端。
显式分离 upload/download 入口也必须由部署保证二者到达共享会话状态的服务端。

```bash
make build-xray
# 分别启动 server、Caddy（使用反代时）和对应 client 后：
curl --proxy http://127.0.0.1:2080 http://example.com
curl --proxy http://127.0.0.1:2080 https://example.com
# E2E 仅验证本地 Caddy TLS 反代：HTTP/1.1/h2c 后端，共 2 项。
# 需要 Go、caddy；使用本地 HTTP/HTTPS 源站和临时证书，不访问公网。
./tests/e2e/run_xray_tests.sh -test XHTTP
```

### 反代与协议

当前 XHTTP 服务端仅接受 HTTP/1.1 与 HTTP/2；HTTP/1.0 请求返回 505，HTTP/3 尚未实现。
GET 响应头在首次读取时等待，最多 10 秒；因此 connect 成功不代表远端已接受 GET/POST，
远端 HTTP 拒绝会在后续 IO 暴露，不会自动重放已经发送的业务数据。
XHTTP E2E 仅保留本地 Caddy 矩阵，不包含 Nginx 或公网访问验证。

### HTTP 层优化约定

`packet-up` 的收益来自“短请求 + 明确长度”，HTTP 层因此不再叠加额外改造：

- 不加 base64：载荷全程走二进制 body，base64 会让体积增加约 1/3。
- 不启用 gzip/br：隧道内通常是 TLS 等已加密载荷，压不动，只增加 CPU 和流式 flush 延迟；
  客户端不发送 `Accept-Encoding`，反代侧也不要对 XHTTP 路径开启压缩。
- 不手动设置 `Transfer-Encoding`/chunked：HTTP/2 用 DATA 帧加 END_STREAM 表达消息体，禁止传输层 chunked；
  上传 POST 必须带准确的 `Content-Length`（缺失返回 411，长度不符返回 400，超限返回 413）；
  下载 GET 的响应框架交给 hyper 决定，HTTP/1.1 下由它自行使用 chunked，不要手写。
- 不加类型/编码头或缩小包长：上传是串行等 ACK 的，吞吐上限约为 `单包大小 ÷ RTT`
  （64 KiB 单包：RTT 50 ms ≈ 10 Mbps，RTT 200 ms ≈ 2.6 Mbps），每 64 KiB 的头部开销不到 1%，
  消除该瓶颈只能靠加大在途窗口，而不是调整 HTTP 头。
- 下载方向没有逐包 ACK，单个长 GET 的吞吐由 HTTP/2 流控窗口与 TCP 决定，是真正承载大流量的通道；
  窗口由 `http2InitialWindowSize`（默认 4 MiB）控制，高 BDP 链路可继续加大。

## 快速开始

### 构建

```bash
cargo build --release
```

生成：

- `target/release/xray-rs`

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

`run` 支持选择 tokio 运行时线程模型（默认 `single`）：

```bash
xray-rs run -c config.yaml --thread single
xray-rs run -c config.yaml --thread multi
```

## 主机 eBPF 能力检测

独立二进制 `ebpf-probe` 通过系统 `bpftool feature probe kernel` 检测当前
Linux 主机的 eBPF 能力，包括内核配置、程序类型、map 类型、helper 等。
需先安装 `bpftool` 并确保它在运行用户的 `PATH` 中，具体探测范围取决于
bpftool 和内核版本，不包含网卡硬件 offload 检测。

```bash
make build-ebpf-probe
sudo ./target/debug/ebpf-probe
sudo ./target/debug/ebpf-probe --json
# 仅检测非特权进程可用的能力，不代表主机完整支持情况
./target/debug/ebpf-probe --unprivileged
```

默认输出可读报告，`--json` 输出 bpftool JSON 报告。完整探测通常需要 root
或相应 capabilities；权限不足时返回非零，不自动降级为非特权探测。
非 Linux、bpftool 缺失或探测执行失败同样返回非零并向 stderr 输出错误。
报告中的单项“不支持”不影响命令成功退出。

探测可能临时创建 BPF map 和加载测试程序，由 bpftool 清理；不会附加业务
程序、修改 sysctl 或挂载文件系统。在容器中运行时，结果还受容器权限和
可见内核配置限制；要了解主机完整能力，请在主机环境执行。

## 最小配置示例

```yaml
log:
  file: /var/log/xray-rs.log   # 可选，缺省输出到 stderr
  level: info                  # 可选，off|error|warn|info|debug|trace，默认 info

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
```

DNS 仅使用系统解析器，不提供应用内 DNS 缓存或 `dns` 配置；旧配置须删除该字段。系统 DNS/hosts 及缓存由操作系统管理。

### freedom 地址偏好与连接重试

```yaml
outbounds:
  - tag: direct
    protocol: freedom
    settings:
      prefer: ipv4              # system（默认）| ipv4 | ipv6
      connectTimeoutMs: 5000    # 默认 5000，必须为正整数
      bpf: false
```

`prefer` 仅调整系统 DNS 返回地址的尝试顺序，不排除另一地址族；同地址族保持原顺序，重复 IP 去重。域名只解析一次，连接失败或超时后依次尝试下一个 IP，每个地址一次。每地址超时包含传输握手，不是转发空闲超时；DNS 使用系统解析器的超时，总连接等待可能随候选地址数量增长。字面 IP 也受连接超时限制。

建立连接后不因 TLS/应用错误重新连接或重放数据。UDP 只在本地 connect 失败时重试，connect 成功不保证远端可达，也不提供数据报级故障切换。

HTTP CONNECT 在出站连接成功后才回复 `200 Connection Established`；连接失败返回 `502`，明确超时返回 `504`。不等待隧道内的客户端 TLS 握手。链式代理的成功保证以其出站协议能够确认的连接阶段为限。通过 `ConnectionSink::handle` 使用库时会自动完成应答；若自行连接并提取 `ProxyStream.inner` / `into_inner()` 转发，须先在出站成功后调用 `confirm_connected()`，失败则调用 `reject_connection()`。

### log 配置

- `file`：日志文件路径（追加写）。缺省时日志输出到 stderr。
- `level`：过滤级别 `off|error|warn|info|debug|trace`，默认 `info`。

### 日志轮转（logrotate + systemctl reload）

配置了 `log.file` 时进程会长期持有该文件的 fd。若 logrotate 不重开文件，
压缩后的日志会继续被写入（`.gz` 被撑大、新文件为空）。xray-rs 收到 `SIGHUP`
会重开日志文件，所以可以用 `postrotate` + `systemctl reload`：

```ini
# /etc/systemd/system/xray-rs.service
[Service]
ExecStart=/usr/local/bin/xray-rs run -c /etc/xray-rs/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
```

```
# /etc/logrotate.d/xray-rs
/var/log/xray-rs.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl reload xray-rs >/dev/null 2>&1 || true
    endscript
}
```

完整示例见 `example/xray-rs.service` 与 `example/logrotate-xray-rs`。
注意：`SIGHUP` 只重开日志文件，不重载配置；改配置仍需重启服务。

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

## rsdns

独立 DNS 服务器已迁移至独立仓库：[`rsdns`](https://github.com/yylt/xray-rs/tree/main/rsdns)（`rsdns/` 目录内为独立 crate，含完整 README、CI、测试与设计文档）。

## 说明

文档内容基于当前 `src` 实现整理；若实现变化，请以源码为准。
