mod app;
pub mod build_info;
pub mod command;
pub mod common;
pub mod generated;
pub mod proxy;
pub mod route;
pub mod transport;

#[cfg(all(feature = "mimalloc", feature = "jemalloc"))]
compile_error!("features 'mimalloc' and 'jemalloc' cannot be enabled at the same time");

pub use crate::command::root;

// Include generated gRPC code
pub mod grpc_transport {
    pub use crate::generated::grpc_generated::*;
}
