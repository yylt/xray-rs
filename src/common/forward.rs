use crate::common::stats;
use crate::transport::TrStream;
use tokio::io::AsyncWriteExt;

const DEFAULT_BUF_SIZE: usize = 64 * 1024;

pub async fn forward(mut local: TrStream, mut remote: TrStream) -> std::io::Result<(u64, u64)> {
    let result =
        tokio::io::copy_bidirectional_with_sizes(&mut local, &mut remote, DEFAULT_BUF_SIZE, DEFAULT_BUF_SIZE).await;

    let _ = local.shutdown().await;
    let _ = remote.shutdown().await;

    if let Ok((uplink, downlink)) = result {
        let stats = stats::shared_stats();
        let global_stats = stats.read().await.global_stats();
        global_stats.record_uplink(uplink);
        global_stats.record_downlink(downlink);
        Ok((uplink, downlink))
    } else {
        result
    }
}
