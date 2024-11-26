use std::io;
use clap;


#[derive(Debug, clap::Args)]
pub struct Version;

impl Version {
    pub fn run(&self) -> io::Result<()> {
        Ok(())
    }
}