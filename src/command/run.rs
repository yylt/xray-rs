use clap;
use std::io;
use serde_json::{self,Value};

#[derive(Debug, clap::Args)]
pub struct Run {
    #[arg(short, long, value_name = "config filepath", default_value = "config.json")]
    config: Option<String>,
}


impl Run {
    pub fn run(&self) -> io::Result<()> {
        Ok(())
    }
}