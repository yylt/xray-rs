use clap;
use std::io;

use serde::{Serialize, Deserialize};
use crate::app;
#[derive(Debug, clap::Args)]
pub struct Run {
    #[arg(short, long, value_name = "config filepath", default_value = "config.json")]
    config: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    
    outbounds: Option<Vec::<app::Outbound>>,

    inbounds: Option<Vec::<app::Inbound>>,

    routing: Option<app::Routing>,
}



impl Run {
    pub fn run(&self) -> io::Result<()> {
        Ok(())
    }
}