use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};

/// Configuration that is only read once, at program start
///
/// This settings can't change without a restart.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct StaticConf {
    /// Path of the config file
    #[arg(short, long, env, default_value = "./config.toml")]
    pub config_path: PathBuf,
    /// Address and port to listen on
    #[arg(short, long, env, default_value = "127.0.0.1:1080")]
    pub listen_addr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DynConf {
    /// The upstream server and port
    pub upstream_addr: String, // Just one for now
}

impl DynConf {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut f = File::open(path)?;
        let mut buf = vec![];
        f.read_to_end(&mut buf)?;

        Ok(toml::from_slice(&buf)?)
    }
}
