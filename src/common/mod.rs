pub mod common;

use std::net;
use anyhow::{Result};
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use tokio::io::{AsyncRead, AsyncWrite};


pub struct StreamCtx <T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync> {
    pub stream: T,
    pub dest: common::Address,
    pub in_tag: String,
    pub out_tag: Option<String>,
}


//  Process(ctx context.Context, network net.Network, conn internet.Connection, dispatcher routing.Dispatcher)
#[async_trait]
pub trait Inbounder {
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug;

    // support types
    fn network(&self) -> Vec<common::Network>;

    // tag, used by router(match inbounder) and logger
    fn tag(&self) -> String;

    // establish with peer(layer 4), should try until success internel.
    fn start(&self);

    // handshake with downstream
    // tr: from async runtime, should support transport protocol(tcp, grpc, tls...)
    async fn process(&self, network: common::Network, tr: Self::Stream) -> Result<StreamCtx<Self::Stream>>;
}

//  Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error
#[async_trait]
pub trait Outbounder {
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug;

    // support types
    fn network(&self) -> Vec<common::Network>;

    // tag, used by router(match inbounder) and logger
    fn tag(&self) -> String;

    // establish with peer(layer 4), should try until success internel.
    fn start(&self);

    async fn process(&self, downstream: StreamCtx<Self::Stream>) -> Result<()>;
}

