use xray_rs::{build_info, common::rslog, common::tls::install_crypto_provider, root};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    install_crypto_provider();

    let _guard = rslog::init(log::LevelFilter::Info);

    build_info::log_startup_info(env!("CARGO_PKG_NAME"));

    if let Err(e) = root::execute() {
        println!("execute error: {e}");
    }
}
