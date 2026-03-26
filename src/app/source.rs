use crate::{
    common::{Address, BoxStream},
    proxy::{Inbounder, ProxyStream},
};

/// 流量来源
pub enum ConnectionSource {
    Listen(ListenSource),
    Daemon(DaemonSource),
}

impl ConnectionSource {
    pub async fn run_listen(self) -> Option<BoxStream<ProxyStream, std::io::Error>> {
        match self {
            ConnectionSource::Listen(ls) => Some(ls.run().await),
            ConnectionSource::Daemon(_) => None,
        }
    }

    pub async fn run_daemon(self) -> std::io::Result<()> {
        match self {
            ConnectionSource::Daemon(ds) => ds.run().await,
            ConnectionSource::Listen(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "listen source cannot be run as daemon",
            )),
        }
    }

    pub fn is_daemon(&self) -> bool {
        matches!(self, ConnectionSource::Daemon(_))
    }
}

/// 传统监听模式
pub struct ListenSource {
    pub tag: String,
    pub inbounder: Inbounder,
    pub listen_addr: Address,
}

impl ListenSource {
    /// 开始监听，产生 ProxyStream 流，带上 inbound_tag
    pub async fn run(self) -> BoxStream<ProxyStream, std::io::Error> {
        let tag = self.tag.clone();
        let raw = self.inbounder.listen(self.listen_addr).await;

        use tokio_stream::StreamExt;
        let tagged = raw.map(move |r| r.map(|s| s.with_tag(tag.clone())));
        Box::pin(tagged)
    }
}

/// Daemon mode source: run as background daemon with exponential backoff on failure
pub struct DaemonSource {
    pub inbounder: Inbounder,
    pub listen_addr: Address,
}

impl DaemonSource {
    pub async fn run(self) -> std::io::Result<()> {
        self.inbounder.run(self.listen_addr).await
    }
}
