use std::process::{Command, ExitCode};

use clap::Parser;

#[derive(Debug, Parser)]
#[command(about = "Probe Linux host eBPF capabilities using the system bpftool")]
struct Args {
    /// Output the bpftool report as JSON
    #[arg(long)]
    json: bool,

    /// Probe only capabilities available without elevated privileges
    #[arg(long)]
    unprivileged: bool,
}

fn probe_command(args: &Args) -> Command {
    let mut command = Command::new("bpftool");
    if args.json {
        command.arg("--json");
    }
    command.args(["feature", "probe", "kernel"]);
    if args.unprivileged {
        command.arg("unprivileged");
    }
    command
}

fn execute(command: &mut Command) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("cannot execute bpftool: {error}; install bpftool and ensure it is in PATH"))?;
    if !status.success() {
        return Err(format!(
            "bpftool probe failed ({status}); see its diagnostic above. \
             Full probing requires elevated privileges (try sudo); \
             use --unprivileged only for a restricted probe."
        ));
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();
    if std::env::consts::OS != "linux" {
        eprintln!("ebpf-probe requires Linux");
        return ExitCode::FAILURE;
    }
    match execute(&mut probe_command(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ebpf-probe: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;

    use super::*;

    #[test]
    fn probe_arguments() {
        for (input, expected) in [
            (vec!["ebpf-probe"], vec!["feature", "probe", "kernel"]),
            (
                vec!["ebpf-probe", "--json", "--unprivileged"],
                vec!["--json", "feature", "probe", "kernel", "unprivileged"],
            ),
        ] {
            let args = Args::try_parse_from(input).unwrap();
            let command = probe_command(&args);
            assert_eq!(command.get_program(), "bpftool");
            assert_eq!(command.get_args().collect::<Vec<_>>(), expected);
        }
        assert!(Args::try_parse_from(["ebpf-probe", "--unknown"]).is_err());
    }

    #[test]
    fn missing_tool_is_an_error() {
        let error = execute(&mut Command::new("/nonexistent-ebpf-probe-test/bpftool")).unwrap_err();
        assert!(error.contains("cannot execute bpftool"));
    }

    #[test]
    fn failed_probe_is_not_reported_as_unsupported() {
        // Reuse the test harness to obtain a portable, unsuccessful child process.
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--invalid-ebpf-probe-test-option")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let error = execute(&mut command).unwrap_err();
        assert!(error.contains("probe failed"));
        assert!(error.contains("privileges"));
    }
}
