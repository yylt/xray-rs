use clap;
use std::io;

#[derive(Debug, clap::Args)]
pub struct Version;

impl Version {
    pub fn run(&self) -> io::Result<()> {
        Ok(())
    }
}
