use xray_rs::{common::tls::install_crypto_provider, root};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    install_crypto_provider();

    if let Err(e) = root::execute() {
        println!("execute error: {e}");
    }
}
