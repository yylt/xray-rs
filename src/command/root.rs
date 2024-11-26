use super::{version,run};
use std::io;
use clap::Parser;

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
        Root::Version(x) => {
            x.run()
        },
        Root::Run(x) => {
            x.run()
        }
        _ => Err(io::ErrorKind::NotFound.into())
    }
}