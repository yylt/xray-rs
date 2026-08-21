mod config;
mod metrics;
mod plugins;
mod query;
mod server;
mod upstream;

use clap::Parser;
use log::error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use xray_rs::common::rslog;

use config::Config;
use plugins::metrics::MetricsConfig;
use server::{DnsServer, Pipeline};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(
    name = "rsdns",
    version = concat!(
        env!("XRAY_RS_VERSION"),
        "\ncommit: ",
        env!("XRAY_RS_GIT_COMMIT"),
        "\nbranch: ",
        env!("XRAY_RS_GIT_BRANCH"),
        "\nrustc: ",
        env!("XRAY_RS_RUSTC_VERSION"),
        "\ntarget: ",
        env!("XRAY_RS_BUILD_TARGET"),
        "\nprofile: ",
        env!("XRAY_RS_BUILD_PROFILE"),
        "\nbuilt: ",
        env!("XRAY_RS_BUILD_TIME"),
    ),
    about,
    long_about = None
)]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "rsdns.yaml")]
    config: PathBuf,
    /// Number of tokio worker threads (multi-thread runtime only;
    /// default = available parallelism).
    #[arg(short = 't', long = "threads")]
    threads: Option<usize>,
    /// Tokio runtime thread model: `multi` (default) or `single`.
    #[arg(long = "thread-model", default_value = "multi", value_parser = ["single", "multi"])]
    thread_model: String,
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let _guard = rslog::init(log::LevelFilter::Info);

    let config = match Config::from_file(&args.config.to_string_lossy()) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to load config {}: {}", args.config.display(), e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let rt = match build_runtime(&args) {
        Ok(rt) => rt,
        Err(e) => {
            error!("failed to build tokio runtime: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    match rt.block_on(run(config)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            error!("rsdns exited with error: {}", e);
            std::process::ExitCode::FAILURE
        }
    }
}

/// Builds the tokio runtime from the `--thread-model` / `--threads` options.
fn build_runtime(args: &Args) -> std::io::Result<tokio::runtime::Runtime> {
    match args.thread_model.as_str() {
        "single" => tokio::runtime::Builder::new_current_thread().enable_all().build(),
        _ => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            if let Some(n) = args.threads {
                builder.worker_threads(n);
            }
            builder.enable_all().build()
        }
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 共享指标注册表。
    let metrics = metrics::MetricsRegistry::new();

    // 2. 初始化各管道阶段（固定顺序；groups 为前置阶段；upstreams 组装后
    //    注入 rules 阶段，供 forward/cname 直接查询）。
    let logs = plugins::logs::init(&config, &metrics);
    let hosts = plugins::hosts::init(&config, &metrics);
    let groups = plugins::groups::init(&config, &metrics);
    let cache = plugins::cache::init(&config, &metrics);
    let upstreams = upstream::init(&config, &metrics).await?;
    let rules = plugins::rules::init(&config, &metrics, upstreams);

    let pipeline = Pipeline {
        logs,
        hosts,
        groups,
        cache,
        rules,
    };
    let server = Arc::new(DnsServer::new(pipeline));

    // 3. 并发启动：UDP/TCP 监听 + metrics HTTP 端点。
    let mut tasks = tokio::task::JoinSet::new();
    for bind in &config.binds {
        let addr: SocketAddr = parse_bind(&bind.address)?;
        let is_tcp = bind.address.starts_with("tcp://");
        let server = server.clone();
        if is_tcp {
            tasks.spawn(async move {
                if let Err(e) = server.serve_tcp(addr).await {
                    error!("TCP listener on {} failed: {}", addr, e);
                }
            });
        } else {
            tasks.spawn(async move {
                if let Err(e) = server.serve_udp(addr).await {
                    error!("UDP listener on {} failed: {}", addr, e);
                }
            });
        }
    }

    // metrics 插件：配置了 metrics 段才启动 HTTP 端点。
    if let Some(cfg) = metrics_config(&config) {
        let registry = metrics.clone();
        tasks.spawn(async move {
            if let Err(e) = plugins::metrics::serve_metrics(cfg, registry).await {
                error!("metrics server failed: {}", e);
            }
        });
    }

    // 4. 等待任意 listener 结束（通常不会）。
    if let Some(Err(e)) = tasks.join_next().await {
        error!("listener task panicked: {}", e);
    }

    // 5. 关闭前 flush 日志。
    server.flush_logs().await;
    Ok(())
}

fn parse_bind(s: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let s = s.strip_prefix("tcp://").unwrap_or(s);
    s.parse::<SocketAddr>().map_err(|e| e.into())
}

fn metrics_config(config: &Config) -> Option<MetricsConfig> {
    plugins::metrics::config(config)
}
