use std::{
    fs, io,
    process::Command,
    sync::{Arc, Mutex, Weak},
};

use aya::{maps::SockHash, programs::SkSkb, Ebpf};

mod session;

pub use session::Outcome;

const SOURCE: &str = include_str!("bpf/relay.c");

/// Owns unpinned relay maps, programs, and attachments. Dropping it detaches them.
/// Maps `sockets` and `targets` are SOCKHASH<u64, u32>; `peers` is HASH<u64, u64>.
/// Only `sockets` has attached programs. Populate targets, peers, and counters
/// before registering source sockets. Counters are HASH<u64, [u64; 2]> holding
/// redirect-admitted bytes and helper errors, not proof of egress delivery.
pub struct BpfRelay {
    pub(crate) ebpf: Mutex<Ebpf>,
}

impl BpfRelay {
    /// Share one unpinned runtime instance across enabled freedom outbounds.
    pub fn shared() -> io::Result<Arc<Self>> {
        static INSTANCE: Mutex<Weak<BpfRelay>> = Mutex::new(Weak::new());
        let mut instance = INSTANCE
            .lock()
            .map_err(|_| io::Error::other("BPF initialization lock poisoned"))?;
        if let Some(relay) = instance.upgrade() {
            return Ok(relay);
        }
        let relay = Arc::new(Self::load()?);
        *instance = Arc::downgrade(&relay);
        Ok(relay)
    }

    pub fn load() -> io::Result<Self> {
        let object = compile(SOURCE)?;
        let mut ebpf = Ebpf::load(&object).map_err(|error| {
            io::Error::other(format!(
                "load BPF relay object: {error}; check kernel SOCKHASH/SK_SKB support, \
                 BPF privileges (root or appropriate capabilities), and the memlock limit"
            ))
        })?;
        let sockets = SockHash::<_, u64>::try_from(
            ebpf.map("sockets")
                .ok_or_else(|| io::Error::other("BPF relay object is missing map sockets"))?,
        )
        .map_err(|error| io::Error::other(format!("open BPF relay socket map: {error}")))?;
        let map_fd = sockets.fd().try_clone()?;
        for name in ["relay_parser", "relay_verdict"] {
            let program: &mut SkSkb = ebpf
                .program_mut(name)
                .ok_or_else(|| io::Error::other(format!("BPF relay object is missing {name}")))?
                .try_into()
                .map_err(|error| io::Error::other(format!("open BPF program {name}: {error}")))?;
            program.load().map_err(|error| {
                io::Error::other(format!(
                    "load BPF program {name}: {error}; check SK_SKB helper support, \
                     BPF privileges, and the memlock limit"
                ))
            })?;
            program
                .attach(&map_fd)
                .map_err(|error| io::Error::other(format!("attach BPF program {name} to sockets: {error}")))?;
        }
        Ok(Self { ebpf: Mutex::new(ebpf) })
    }
}

fn compile(source: &str) -> io::Result<Vec<u8>> {
    let directory = tempfile::tempdir()?;
    let source_path = directory.path().join("relay.c");
    let object_path = directory.path().join("relay.o");
    fs::write(&source_path, source)?;
    let target = if cfg!(target_endian = "little") {
        "bpfel"
    } else {
        "bpfeb"
    };
    let output = Command::new("clang")
        .args(["-target", target, "-O2", "-g", "-c"])
        .arg(&source_path)
        .arg("-o")
        .arg(&object_path)
        .output()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("run clang for BPF relay: {error}; install clang with the BPF backend"),
            )
        })?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "compile BPF relay with clang ({status}): {stderr}",
            status = output.status,
            stderr = String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }
    fs::read(object_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_relay_compiles_to_bpf_elf() {
        let object = match compile(SOURCE) {
            Ok(object) => object,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("skipping BPF compile test: {error}");
                return;
            }
            Err(error) => panic!("{error}"),
        };
        // Validate the ELF64 header without creating kernel maps or loading programs.
        assert!(object.len() >= 64);
        assert_eq!(&object[..5], b"\x7fELF\x02");
        let little_endian = cfg!(target_endian = "little");
        assert_eq!(object[5], if little_endian { 1 } else { 2 });
        let machine = [object[18], object[19]];
        assert_eq!(
            if little_endian {
                u16::from_le_bytes(machine)
            } else {
                u16::from_be_bytes(machine)
            },
            247, // EM_BPF
        );
    }

    #[test]
    fn compilation_errors_include_clang_diagnostics() {
        let error = compile("#error relay_test_diagnostic").unwrap_err();
        if error.kind() == io::ErrorKind::NotFound {
            eprintln!("skipping BPF compile test: {error}");
            return;
        }
        let message = error.to_string();
        assert!(message.contains("compile BPF relay with clang"), "{message}");
        assert!(message.contains("relay_test_diagnostic"), "{message}");
    }
}
