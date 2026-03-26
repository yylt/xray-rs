use super::{run, version};
use clap::Parser;
use std::io;

#[derive(Debug, Parser)]
#[command(name = "xray")]
#[command(about = "proxies", long_about = None)]
enum Root {
    Run(run::Run),
    Version(version::Version),
}

#[allow(dead_code)]
pub fn execute() -> io::Result<()> {
    match Root::parse() {
        Root::Version(x) => x.run(),
        Root::Run(x) => x.run(),
    }
}
