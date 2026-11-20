use std::{
    io,
    net::Shutdown,
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, MutexGuard,
    },
    time::Duration,
};

use aya::{
    maps::{HashMap, MapError, SockHash},
    Ebpf,
};
use socket2::SockRef;
use tokio::{io::Interest, net::TcpStream, time::sleep};

use super::BpfRelay;
use crate::common::stats::TrafficCounters;

const POLL: Duration = Duration::from_millis(10);
const TCP_ESTABLISHED: u8 = 1;
/// `linux/bpf.h` map update flag; the `libc` crate does not export it.
const BPF_NOEXIST: u64 = 1;

/// How a relay attempt ended.
#[derive(Debug)]
pub enum Outcome {
    /// The kernel moved the payload; both sockets are finished with.
    Kernel,
    /// Nothing was armed and no payload was consumed, so the caller must
    /// forward the returned sockets in userspace.
    Userspace(TcpStream, TcpStream),
}

/// Receive state sampled before arming; reading it changes no queue.
struct Activation {
    keys: [u64; 2],
    consumed: [u64; 2],
    acked: [u64; 2],
}

/// Only `Unarmed` is safe to fall back from: a registered source can already
/// redirect payload, so it would bypass or reorder userspace writes.
enum Registration {
    Armed,
    Unarmed(io::Error),
    PartiallyArmed(io::Error),
}

impl BpfRelay {
    /// Transfer exclusively through SK_SKB once armed. Relay errors then close
    /// both streams instead of falling back to userspace copying.
    pub async fn forward(self: Arc<Self>, local: TcpStream, remote: TcpStream) -> io::Result<Outcome> {
        self.forward_with_counters(local, remote, TrafficCounters::default())
            .await
    }

    /// Publish redirect-admitted bytes, not ACKed or delivered bytes. Buffered
    /// prefixes and any unarmed userspace fallback are counted by the caller.
    pub async fn forward_with_counters(
        self: Arc<Self>,
        local: TcpStream,
        remote: TcpStream,
        counters: TrafficCounters,
    ) -> io::Result<Outcome> {
        let streams = [&local, &remote];
        let activation = match prepare(streams).await {
            Ok(activation) => activation,
            Err(error) => {
                log::debug!("BPF relay not started, forwarding in userspace: {error}");
                return Ok(Outcome::Userspace(local, remote));
            }
        };
        let session = Session {
            relay: self,
            keys: activation.keys,
            streams,
            counters,
            reported: [AtomicU64::new(0), AtomicU64::new(0)],
        };
        match session.register(streams) {
            Registration::Armed => log::debug!("BPF relay armed for both directions"),
            Registration::Unarmed(error) => {
                // Undo every created entry before userspace takes the payload.
                drop(session);
                log::debug!("BPF relay not armed, forwarding in userspace: {error}");
                return Ok(Outcome::Userspace(local, remote));
            }
            Registration::PartiallyArmed(error) => return Err(error),
        }
        let [local_key, remote_key] = activation.keys;
        let [local_consumed, remote_consumed] = activation.consumed;
        let [local_acked, remote_acked] = activation.acked;
        tokio::try_join!(
            session.direction(&local, &remote, local_key, local_consumed, remote_acked),
            session.direction(&remote, &local, remote_key, remote_consumed, local_acked),
        )?;
        Ok(Outcome::Kernel)
    }
}

/// Drain queued egress and snapshot receive state so arming starts from a known
/// sequence position. Every step here leaves the sockets untouched by redirect.
async fn prepare(streams: [&TcpStream; 2]) -> io::Result<Activation> {
    for stream in streams {
        while queue_len(stream, libc::TIOCOUTQ)? != 0 {
            check_socket(stream)?;
            sleep(POLL).await;
        }
    }
    let keys = [cookie(streams[0])?, cookie(streams[1])?];
    let acked = [tcp_info(streams[0])?.acked, tcp_info(streams[1])?.acked];
    let consumed = [consumed_bytes(streams[0]).await?, consumed_bytes(streams[1]).await?];
    Ok(Activation { keys, consumed, acked })
}

struct Session<'a> {
    relay: Arc<BpfRelay>,
    keys: [u64; 2],
    streams: [&'a TcpStream; 2],
    counters: TrafficCounters,
    reported: [AtomicU64; 2],
}

/// Monotonic snapshots can repeat; only publish each admitted byte once.
fn record_admitted(counters: &TrafficCounters, reported: &AtomicU64, bytes: u64, uplink: bool) {
    let previous = reported.fetch_max(bytes, Ordering::Relaxed);
    let delta = bytes.saturating_sub(previous);
    if uplink {
        counters.record_uplink(delta);
    } else {
        counters.record_downlink(delta);
    }
}

impl Session<'_> {
    fn lock(&self) -> io::Result<MutexGuard<'_, Ebpf>> {
        self.relay
            .ebpf
            .lock()
            .map_err(|_| io::Error::other("BPF relay lock poisoned"))
    }

    fn register(&self, streams: [&TcpStream; 2]) -> Registration {
        if let Err(error) = self.register_peers(streams) {
            return Registration::Unarmed(error);
        }
        self.register_sources(streams)
    }

    /// Every redirect destination must exist before a source can redirect.
    fn register_peers(&self, streams: [&TcpStream; 2]) -> io::Result<()> {
        let mut ebpf = self.lock()?;
        let map = |name| io::Error::other(format!("BPF relay missing map {name}"));
        {
            let mut targets = SockHash::<_, u64>::try_from(ebpf.map_mut("targets").ok_or_else(|| map("targets"))?)
                .map_err(map_error)?;
            for (key, stream) in self.keys.into_iter().zip(streams) {
                targets
                    .insert(&key, stream.as_raw_fd(), BPF_NOEXIST)
                    .map_err(map_error)?;
            }
        }
        {
            let mut peers = HashMap::<_, u64, u64>::try_from(ebpf.map_mut("peers").ok_or_else(|| map("peers"))?)
                .map_err(map_error)?;
            peers
                .insert(&self.keys[0], &self.keys[1], BPF_NOEXIST)
                .map_err(map_error)?;
            peers
                .insert(&self.keys[1], &self.keys[0], BPF_NOEXIST)
                .map_err(map_error)?;
        }
        {
            let mut counters =
                HashMap::<_, u64, [u64; 2]>::try_from(ebpf.map_mut("counters").ok_or_else(|| map("counters"))?)
                    .map_err(map_error)?;
            for key in self.keys {
                counters.insert(&key, &[0, 0], BPF_NOEXIST).map_err(map_error)?;
            }
        }
        Ok(())
    }

    /// Attaching a source is the point of no return: its parser can redirect as
    /// soon as it is in the map, so only a failure before the first insert may
    /// still fall back to userspace copying.
    fn register_sources(&self, streams: [&TcpStream; 2]) -> Registration {
        let mut armed = false;
        {
            let mut ebpf = match self.lock() {
                Ok(ebpf) => ebpf,
                Err(error) => return Registration::Unarmed(error),
            };
            let sockets = ebpf
                .map_mut("sockets")
                .ok_or_else(|| io::Error::other("BPF relay missing map sockets"))
                .and_then(|map| SockHash::<_, u64>::try_from(map).map_err(map_error));
            let mut sources = match sockets {
                Ok(sources) => sources,
                Err(error) => return Registration::Unarmed(error),
            };
            for (key, stream) in self.keys.into_iter().zip(streams) {
                if let Err(error) = sources.insert(&key, stream.as_raw_fd(), BPF_NOEXIST) {
                    let error = map_error(error);
                    return if armed {
                        Registration::PartiallyArmed(error)
                    } else {
                        Registration::Unarmed(error)
                    };
                }
                armed = true;
            }
        }
        // Linux tcp_set_rcvlowat invokes tcp_data_ready -> sk_data_ready,
        // scheduling the newly attached parser even for already queued payload.
        for stream in streams {
            let lowat: libc::c_int = 1;
            // SAFETY: the fd remains owned by stream; value and size match SO_RCVLOWAT.
            let result = unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVLOWAT,
                    (&lowat as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if result == -1 {
                return Registration::PartiallyArmed(io::Error::last_os_error());
            }
        }
        Registration::Armed
    }

    fn admitted(&self, key: u64) -> io::Result<u64> {
        let ebpf = self.lock()?;
        let counters = HashMap::<_, u64, [u64; 2]>::try_from(
            ebpf.map("counters")
                .ok_or_else(|| io::Error::other("BPF relay missing counters"))?,
        )
        .map_err(map_error)?;
        let [bytes, errors] = counters.get(&key, 0).map_err(map_error)?;
        let direction = usize::from(key != self.keys[0]);
        record_admitted(&self.counters, &self.reported[direction], bytes, direction == 0);
        if errors != 0 {
            return Err(io::Error::other("BPF socket redirect failed"));
        }
        Ok(bytes)
    }

    async fn direction(
        &self,
        source: &TcpStream,
        destination: &TcpStream,
        key: u64,
        consumed: u64,
        acked: u64,
    ) -> io::Result<()> {
        loop {
            check_socket(source)?;
            check_socket(destination)?;
            self.admitted(key)?;
            // Periodic checks also detect asynchronous redirect errors when no
            // further socket readiness notification arrives.
            let ready = tokio::select! {
                ready = source.ready(Interest::READABLE) => Some(ready?),
                () = sleep(POLL) => None,
            };
            if ready.is_some_and(|ready| ready.is_read_closed()) {
                break;
            }
            if ready.is_some() {
                // Clear ordinary cached readability without reading application
                // payload. EOF readiness is retained by Tokio independently.
                let _ = source.try_io(Interest::READABLE, || Err::<(), _>(io::Error::from(io::ErrorKind::WouldBlock)));
                sleep(POLL).await;
            }
        }
        let expected = tcp_info(source)?
            .received
            .checked_sub(consumed)
            .and_then(|bytes| bytes.checked_sub(1)) // FIN occupies one TCP sequence byte.
            .ok_or_else(|| io::Error::other("BPF relay receive accounting underflow"))?;
        loop {
            check_socket(source)?;
            check_socket(destination)?;
            let admitted = self.admitted(key)?;
            if admitted > expected {
                return Err(io::Error::other("BPF relay receive accounting mismatch"));
            }
            // FIONREAD alone misses payload already moved to the parser's work
            // queue. Compare final received sequence bytes before freezing count.
            if queue_len(source, libc::FIONREAD)? == 0 && admitted == expected {
                let final_ack = acked
                    .checked_add(admitted)
                    .ok_or_else(|| io::Error::other("BPF relay ACK accounting overflow"))?;
                if tcp_info(destination)?.acked >= final_ack {
                    break;
                }
            }
            sleep(POLL).await;
        }
        SockRef::from(destination).shutdown(Shutdown::Write)
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // Even a poisoned lock must permit best-effort teardown. Source removal
        // precedes targets/metadata; cookie identities cannot alias recycled fds.
        let mut ebpf = self.relay.ebpf.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(map) = ebpf.map_mut("sockets") {
            if let Ok(mut sockets) = SockHash::<_, u64>::try_from(map) {
                for key in self.keys {
                    if let Err(error) = sockets.remove(&key) {
                        let missing = matches!(&error, MapError::KeyNotFound)
                            || matches!(&error, MapError::SyscallError(error)
                                if error.io_error.raw_os_error() == Some(libc::ENOENT));
                        if !missing {
                            log::error!("BPF source removal failed; final statistics may be incomplete: {error}");
                        }
                    }
                }
            }
        }
        // Linux strparser workers hold lock_sock while running the verdict.
        // Removing sources stops future work but does not wait for an in-flight
        // worker. SO_RCVLOWAT setsockopt takes lock_sock, draining that worker
        // before the final snapshot (audited against Linux v5.15).
        for stream in self.streams {
            if let Err(error) = synchronize_socket(stream) {
                log::error!("BPF socket synchronization failed; final statistics may be incomplete: {error}");
            }
        }
        if let Some(map) = ebpf.map("counters") {
            if let Ok(counters) = HashMap::<_, u64, [u64; 2]>::try_from(map) {
                for (direction, key) in self.keys.into_iter().enumerate() {
                    if let Ok([bytes, _]) = counters.get(&key, 0) {
                        record_admitted(&self.counters, &self.reported[direction], bytes, direction == 0);
                    }
                }
            }
        }
        if let Some(map) = ebpf.map_mut("targets") {
            if let Ok(mut targets) = SockHash::<_, u64>::try_from(map) {
                for key in self.keys {
                    let _ = targets.remove(&key);
                }
            }
        }
        if let Some(map) = ebpf.map_mut("peers") {
            if let Ok(mut peers) = HashMap::<_, u64, u64>::try_from(map) {
                for key in self.keys {
                    let _ = peers.remove(&key);
                }
            }
        }
        if let Some(map) = ebpf.map_mut("counters") {
            if let Ok(mut counters) = HashMap::<_, u64, [u64; 2]>::try_from(map) {
                for key in self.keys {
                    let _ = counters.remove(&key);
                }
            }
        }
    }
}

fn map_error(error: MapError) -> io::Error {
    io::Error::other(format!("BPF relay map: {error}"))
}

fn check_socket(stream: &TcpStream) -> io::Result<()> {
    match stream.take_error()? {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn queue_len(stream: &TcpStream, request: libc::c_ulong) -> io::Result<u32> {
    let mut length: libc::c_int = 0;
    // SAFETY: ioctl receives a valid live socket and writable integer output.
    if unsafe { libc::ioctl(stream.as_raw_fd(), request, &mut length) } == -1 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(length).map_err(|_| io::Error::other("negative TCP queue length"))
}

fn socket_option(stream: &TcpStream, level: libc::c_int, option: libc::c_int, bytes: &mut [u8]) -> io::Result<()> {
    let mut length = bytes.len() as libc::socklen_t;
    // SAFETY: bytes is writable for length bytes, and fd is live for the call.
    if unsafe { libc::getsockopt(stream.as_raw_fd(), level, option, bytes.as_mut_ptr().cast(), &mut length) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if (length as usize) < bytes.len() {
        return Err(io::Error::other("kernel returned truncated TCP socket option"));
    }
    Ok(())
}

fn synchronize_socket(stream: &TcpStream) -> io::Result<()> {
    let mut bytes = [0; size_of::<libc::c_int>()];
    socket_option(stream, libc::SOL_SOCKET, libc::SO_RCVLOWAT, &mut bytes)?;
    let lowat = libc::c_int::from_ne_bytes(bytes);
    // SAFETY: fd is live and lowat retains the socket's current integer option.
    if unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVLOWAT,
            (&lowat as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn cookie(stream: &TcpStream) -> io::Result<u64> {
    let mut bytes = [0; 8];
    socket_option(stream, libc::SOL_SOCKET, libc::SO_COOKIE, &mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

struct TcpInfo {
    state: u8,
    acked: u64,
    received: u64,
}

fn tcp_info(stream: &TcpStream) -> io::Result<TcpInfo> {
    // Stable Linux UAPI offsets: tcpi_bytes_acked=120, bytes_received=128.
    let mut bytes = [0; 136];
    socket_option(stream, libc::IPPROTO_TCP, libc::TCP_INFO, &mut bytes)?;
    Ok(TcpInfo {
        state: bytes[0],
        acked: u64::from_ne_bytes(bytes[120..128].try_into().unwrap()),
        received: u64::from_ne_bytes(bytes[128..136].try_into().unwrap()),
    })
}

async fn consumed_bytes(stream: &TcpStream) -> io::Result<u64> {
    loop {
        check_socket(stream)?;
        let before = tcp_info(stream)?;
        let pending = queue_len(stream, libc::FIONREAD)?;
        let after = tcp_info(stream)?;
        if before.state != TCP_ESTABLISHED || after.state != TCP_ESTABLISHED {
            return Err(io::Error::other("BPF relay activation requires established TCP sockets"));
        }
        if before.received == after.received {
            return after
                .received
                .checked_sub(u64::from(pending))
                .ok_or_else(|| io::Error::other("BPF relay initial receive accounting underflow"));
        }
        sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };

    fn traffic_counters() -> (TrafficCounters, Arc<crate::common::stats::TrafficStats>) {
        let stats = Arc::new(crate::common::stats::TrafficStats::new());
        (
            TrafficCounters {
                inbound: Some(stats.clone()),
                outbound: None,
            },
            stats,
        )
    }

    #[test]
    fn admitted_snapshots_publish_only_new_bytes_in_each_direction() {
        let (mut counters, inbound) = traffic_counters();
        let outbound = Arc::new(crate::common::stats::TrafficStats::new());
        counters.outbound = Some(outbound.clone());
        let reported = [AtomicU64::new(0), AtomicU64::new(0)];
        for (bytes, uplink) in [(7, true), (7, true), (3, true), (11, true), (5, false)] {
            record_admitted(&counters, &reported[usize::from(!uplink)], bytes, uplink);
        }
        for stats in [&inbound, &outbound] {
            assert_eq!((stats.uplink(), stats.downlink()), (11, 5));
        }
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    /// Entry counts for sockets, targets, peers and counters.
    fn map_entry_counts(relay: &BpfRelay) -> [usize; 4] {
        let ebpf = relay.ebpf.lock().unwrap();
        [
            SockHash::<_, u64>::try_from(ebpf.map("sockets").unwrap())
                .unwrap()
                .keys()
                .count(),
            SockHash::<_, u64>::try_from(ebpf.map("targets").unwrap())
                .unwrap()
                .keys()
                .count(),
            HashMap::<_, u64, u64>::try_from(ebpf.map("peers").unwrap())
                .unwrap()
                .keys()
                .count(),
            HashMap::<_, u64, [u64; 2]>::try_from(ebpf.map("counters").unwrap())
                .unwrap()
                .keys()
                .count(),
        ]
    }

    async fn wait_for_counts(relay: &BpfRelay, expected: [usize; 4]) {
        loop {
            if map_entry_counts(relay) == expected {
                return;
            }
            sleep(POLL).await;
        }
    }

    #[tokio::test]
    async fn tcp_info_matches_receive_queue_and_fin_sequence() {
        let (mut client, server) = pair().await;
        let mut lowat_before = [0; size_of::<libc::c_int>()];
        socket_option(&server, libc::SOL_SOCKET, libc::SO_RCVLOWAT, &mut lowat_before).unwrap();
        synchronize_socket(&server).unwrap();
        let mut lowat_after = [0; size_of::<libc::c_int>()];
        socket_option(&server, libc::SOL_SOCKET, libc::SO_RCVLOWAT, &mut lowat_after).unwrap();
        assert_eq!(lowat_before, lowat_after);
        let consumed = consumed_bytes(&server).await.unwrap();
        client.write_all(b"sequence").await.unwrap();
        client.shutdown().await.unwrap();
        timeout(Duration::from_secs(5), async {
            while tcp_info(&server).unwrap().state == TCP_ESTABLISHED {
                sleep(POLL).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(queue_len(&server, libc::FIONREAD).unwrap(), 8);
        assert_eq!(tcp_info(&server).unwrap().received - consumed, 9);
    }

    async fn relay_case(prequeued: bool) {
        timeout(Duration::from_secs(15), async {
            let relay = Arc::new(BpfRelay::load().expect("root/CAP_BPF, SK_SKB, and clang required"));
            let (mut client, local) = pair().await;
            let (remote, mut server) = pair().await;
            let request: Vec<u8> = (0..32768).map(|n| (n % 251) as u8).collect();
            let reply: Vec<u8> = (0..16384).map(|n| (n % 239) as u8).collect();
            let prefix = if prequeued { 4096 } else { 0 };
            if prequeued {
                client.write_all(&request[..prefix]).await.unwrap();
                while queue_len(&local, libc::FIONREAD).unwrap() < prefix as u32 {
                    sleep(POLL).await;
                }
            }
            let owner = relay.clone();
            let (counters, stats) = traffic_counters();
            let forward = tokio::spawn(relay.forward_with_counters(local, remote, counters));
            // Wait until source registration has completed before FIN; sockets
            // already in CLOSE_WAIT cannot be activated in SOCKHASH.
            wait_for_counts(&owner, [2, 2, 2, 2]).await;
            if prequeued {
                let mut received = vec![0; prefix];
                server.read_exact(&mut received).await.unwrap();
                assert_eq!(received, request[..prefix]);
            }
            client.write_all(&request[prefix..]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, request[prefix..]);
            // Reply only after observing EOF: half-close must preserve reverse flow.
            server.write_all(&reply).await.unwrap();
            server.shutdown().await.unwrap();
            let mut received = Vec::new();
            client.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, reply);
            assert!(matches!(forward.await.unwrap().unwrap(), Outcome::Kernel));
            assert_eq!((stats.uplink(), stats.downlink()), (request.len() as u64, reply.len() as u64));
            assert_eq!(map_entry_counts(&owner), [0, 0, 0, 0]);
        })
        .await
        .expect("BPF relay timed out");
    }

    #[tokio::test]
    #[ignore = "requires root/CAP_BPF, kernel SK_SKB support and clang"]
    async fn privileged_bidirectional_half_close() {
        relay_case(false).await;
    }

    #[tokio::test]
    #[ignore = "requires root/CAP_BPF, kernel SK_SKB support and clang"]
    async fn privileged_prequeued_payload_half_close() {
        relay_case(true).await;
    }

    #[tokio::test]
    #[ignore = "requires root/CAP_BPF, kernel SK_SKB support and clang"]
    async fn privileged_unarmed_registration_falls_back_without_replay() {
        timeout(Duration::from_secs(15), async {
            let relay = Arc::new(BpfRelay::load().expect("root/CAP_BPF, SK_SKB, and clang required"));
            let (mut client, local) = pair().await;
            let (remote, mut server) = pair().await;
            // Occupy the inbound cookie so the first target insert fails before
            // any source is armed; every entry must be undone on the way out.
            {
                let mut ebpf = relay.ebpf.lock().unwrap();
                let mut targets = SockHash::<_, u64>::try_from(ebpf.map_mut("targets").unwrap()).unwrap();
                targets.insert(&cookie(&local).unwrap(), local.as_raw_fd(), 0).unwrap();
            }
            let (counters, stats) = traffic_counters();
            let outcome = relay
                .clone()
                .forward_with_counters(local, remote, counters.clone())
                .await
                .unwrap();
            assert_eq!((stats.uplink(), stats.downlink()), (0, 0));
            let (local, remote) = match outcome {
                Outcome::Userspace(local, remote) => (local, remote),
                Outcome::Kernel => panic!("a failed activation must not claim the kernel path"),
            };
            assert_eq!(map_entry_counts(&relay), [0, 0, 0, 0]);
            let copy = tokio::spawn(async move {
                crate::common::forward::StreamForwarder::new()
                    .forward_with_counters(
                        crate::transport::TrStream::Tcp(local),
                        crate::transport::TrStream::Tcp(remote),
                        counters,
                    )
                    .await
            });
            let payload: Vec<u8> = (0..8192).map(|n| (n % 241) as u8).collect();
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
            server.shutdown().await.unwrap();
            copy.await.unwrap().unwrap();
            assert_eq!((stats.uplink(), stats.downlink()), (payload.len() as u64, 0));
            assert_eq!(map_entry_counts(&relay), [0, 0, 0, 0]);
        })
        .await
        .expect("BPF relay timed out");
    }

    #[tokio::test]
    #[ignore = "requires root/CAP_BPF, kernel SK_SKB support and clang"]
    async fn privileged_partial_registration_closes_without_fallback() {
        timeout(Duration::from_secs(15), async {
            let relay = Arc::new(BpfRelay::load().expect("root/CAP_BPF, SK_SKB, and clang required"));
            let (_client, local) = pair().await;
            let (remote, _server) = pair().await;
            // Occupy the outbound cookie only: the inbound source is armed first,
            // so the later failure must close instead of resuming userspace copies.
            {
                let mut ebpf = relay.ebpf.lock().unwrap();
                let mut sockets = SockHash::<_, u64>::try_from(ebpf.map_mut("sockets").unwrap()).unwrap();
                sockets
                    .insert(&cookie(&remote).unwrap(), remote.as_raw_fd(), 0)
                    .unwrap();
            }
            let error = relay.clone().forward(local, remote).await.unwrap_err();
            assert!(error.to_string().contains("BPF relay map"), "{error}");
            assert_eq!(map_entry_counts(&relay), [0, 0, 0, 0]);
        })
        .await
        .expect("BPF relay timed out");
    }

    #[tokio::test]
    #[ignore = "requires root/CAP_BPF, kernel SK_SKB support and clang"]
    async fn privileged_error_and_drop_settle_admitted_deltas() {
        let (_client, local) = pair().await;
        let (remote, _server) = pair().await;
        let relay = Arc::new(BpfRelay::load().expect("root/CAP_BPF, SK_SKB, and clang required"));
        let (counters, stats) = traffic_counters();
        let session = Session {
            relay: relay.clone(),
            keys: [11, 12],
            streams: [&local, &remote],
            counters,
            reported: [AtomicU64::new(0), AtomicU64::new(0)],
        };
        {
            let mut ebpf = relay.ebpf.lock().unwrap();
            let mut map = HashMap::<_, u64, [u64; 2]>::try_from(ebpf.map_mut("counters").unwrap()).unwrap();
            map.insert(&11, &[7, 1], 0).unwrap();
            map.insert(&12, &[3, 0], 0).unwrap();
        }
        assert!(session.admitted(11).is_err());
        assert_eq!((stats.uplink(), stats.downlink()), (7, 0));
        {
            let mut ebpf = relay.ebpf.lock().unwrap();
            let mut map = HashMap::<_, u64, [u64; 2]>::try_from(ebpf.map_mut("counters").unwrap()).unwrap();
            map.insert(&11, &[9, 1], 0).unwrap();
        }
        drop(session);
        assert_eq!((stats.uplink(), stats.downlink()), (9, 3));
        assert_eq!(map_entry_counts(&relay), [0, 0, 0, 0]);
    }

    #[tokio::test]
    #[ignore = "requires root/CAP_BPF, kernel SK_SKB support and clang"]
    async fn privileged_cancellation_releases_map_entries() {
        timeout(Duration::from_secs(15), async {
            let relay = Arc::new(BpfRelay::load().expect("root/CAP_BPF, SK_SKB, and clang required"));
            let (mut client, local) = pair().await;
            let (remote, mut server) = pair().await;
            let owner = relay.clone();
            let (counters, stats) = traffic_counters();
            let forward = tokio::spawn(relay.forward_with_counters(local, remote, counters));
            wait_for_counts(&owner, [2, 2, 2, 2]).await;
            client.write_all(b"before-cancel").await.unwrap();
            let mut received = [0; 13];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"before-cancel");
            while stats.uplink() != 13 {
                sleep(POLL).await;
            }
            assert!(!forward.is_finished(), "statistics must update while the flow is open");
            // Admit another chunk and cancel before requiring the next poll.
            client.write_all(b"tail").await.unwrap();
            let mut last = [0; 4];
            server.read_exact(&mut last).await.unwrap();
            assert_eq!(&last, b"tail");
            forward.abort();
            assert!(forward.await.unwrap_err().is_cancelled());
            wait_for_counts(&owner, [0, 0, 0, 0]).await;
            assert_eq!((stats.uplink(), stats.downlink()), (17, 0));
            // Dropping the sockets closes both sides instead of stranding payload.
            let mut tail = Vec::new();
            let _ = server.read_to_end(&mut tail).await;
            assert!(tail.is_empty());
        })
        .await
        .expect("BPF relay timed out");
    }
}
