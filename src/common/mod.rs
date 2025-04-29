pub mod common;

use anyhow::{Result};
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use tokio::io::{AsyncRead, AsyncWrite};


pub struct StreamCtx <T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync> {
    pub stream: T,
    pub dest: common::Address,
    pub network: common::Network,
    pub in_tag: String,
    pub out_tag: Option<String>,
}


#[async_trait]
pub trait Inbounder {
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug;

    // support types
    fn network(&self) -> Vec<common::Network>;

    // tag, used by router and logger
    fn tag(&self) -> String;

    // start listen
    async fn start(&self) -> Result<StreamCtx<Self::Stream>>;
}

#[async_trait]
pub trait Outbounder {
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug;

    // support networks
    fn network(&self) -> Vec<common::Network>;

    // tag, used by router and logger
    fn tag(&self) -> String;

    // establish with peer(layer 4), try until success internel.
    async fn start(&self);

    // process stream until end
    async fn process(&self, downstream: StreamCtx<Self::Stream>) -> Result<()>;
}

