use clap;
use std::io;

use crate::build_info::BUILD_INFO;

#[derive(Debug, clap::Args)]
pub struct Version;

impl Version {
    pub fn run(&self) -> io::Result<()> {
        println!("{}", BUILD_INFO);
        Ok(())
    }
}
