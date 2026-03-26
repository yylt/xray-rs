mod app;
pub mod command;
pub mod common;
pub mod generated;
pub mod proxy;
pub mod route;
pub mod transport;

pub use crate::command::root;

// Include generated gRPC code
pub mod grpc_transport {
    pub use crate::generated::grpc_generated::*;
}
