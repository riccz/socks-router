use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Read a TOML file with serde
fn read_toml<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(toml::from_slice(&buf)?)
}

/// Parse the CLI args, the env vars and the optional static config file
///
/// The priority is:
///
/// 1. CLI args
/// 2. Env vars
/// 3. Config file
/// 4. Defaults
///
/// This function exits with an error and displays a help message if the CLI
/// args cannot be parsed.
pub fn parse_args_and_read_config() -> Result<StaticConf> {
    let cli_args = CliArgs::parse();
    Ok(match cli_args.config_path {
        None => cli_args.static_conf.into(),
        Some(config_path) => {
            // Can't use logging here, because it's not set up yet
            eprintln!("Using static config at {:?}", config_path);
            let file_conf = read_toml(&config_path)
                .with_context(|| format!("Invalid config file {:?}", config_path))?;
            let mut static_conf = cli_args.static_conf;
            static_conf.update(file_conf);
            static_conf.into()
        }
    })
}

// The only thing that doesn't make sense to write in the config file is it's own path.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Path of the static config file
    #[arg(short, long, env = "SOCKS_ROUTER_CONFIG_PATH")]
    pub config_path: Option<PathBuf>,
    #[command(flatten)]
    static_conf: OptStaticConf,
}

/// Configuration that is only read once, at program start
///
/// This settings can't change without a restart.
///
/// These are all optional because the can be read from both clap and serde.
/// We don't know if they are actually present until they are merged.
///
/// The default values are set by Into<StaticConf>::into
#[derive(Debug, Args, Deserialize)]
struct OptStaticConf {
    /// Address and port to listen on
    #[arg(short, long, env = "SOCKS_ROUTER_LISTEN")]
    pub listen: Option<String>,
    /// Logging level
    #[arg(short = 'v', long, env = "SOCKS_ROUTER_LOG_LEVEL")]
    #[serde(default, with = "serde_opt_tracing_level")]
    pub log_level: Option<tracing::Level>,
    /// Path of the dynamic config
    #[arg(short, long, env = "SOCKS_ROUTER_DYN_CONFIG_PATH")]
    pub dyn_config_path: Option<PathBuf>,
    /// Address and port for the API to listen on
    #[arg(short, long, env = "SOCKS_ROUTER_API_LISTEN")]
    pub api_listen: Option<String>,
    /// Name of the interface to use for upstream sockets
    #[arg(short = 'i', long, env = "SOCKS_ROUTER_UPSTREAM_DEVICE")]
    pub upstream_device: Option<String>,
}

impl Into<StaticConf> for OptStaticConf {
    fn into(self) -> StaticConf {
        let listen = self.listen.unwrap_or("127.0.0.1:1080".into());
        let log_level = self.log_level.unwrap_or(tracing::Level::INFO);
        let dyn_config_path = self.dyn_config_path.unwrap_or("dynconfig.toml".into());
        let api_listen = self.api_listen.unwrap_or("127.0.0.1:5000".into());
        let upstream_device = self.upstream_device;
        StaticConf {
            listen,
            log_level,
            dyn_config_path,
            api_listen,
            upstream_device,
        }
    }
}

impl OptStaticConf {
    pub fn update(&mut self, other: Self) -> &mut Self {
        if self.listen.is_none() {
            self.listen = other.listen;
        }
        if self.log_level.is_none() {
            self.log_level = other.log_level;
        }
        if self.dyn_config_path.is_none() {
            self.dyn_config_path = other.dyn_config_path;
        }
        if self.api_listen.is_none() {
            self.api_listen = other.api_listen;
        }
        if self.upstream_device.is_none() {
            self.upstream_device = other.upstream_device;
        }
        self
    }
}

/// The actual config, after merging the sources
#[derive(Debug)]
pub struct StaticConf {
    /// Address and port to listen on
    pub listen: String,
    /// Logging level
    pub log_level: tracing::Level,
    /// Path of the dynamic config
    pub dyn_config_path: PathBuf,
    /// Address and port for the API to listen on
    pub api_listen: String,
    /// Name of the interface to use for upstream sockets
    pub upstream_device: Option<String>,
}

/// Dynamic config.
///
/// This is updated by the server when the settings are changed via the API.
// FIXME: It's possible to confuse address:port with upstream names. Maybe use a
// wrapper type to distinguish?
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DynConf {
    /// Base settings independent of the connected user
    pub default: DynDefaultConf,
    /// Known upstreams
    pub upstreams: Vec<DynUpstreamConfig>,
    /// Users
    pub users: Vec<DynUserConfig>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DynDefaultConf {
    /// The fallback default upstream name
    pub upstream: String,
    #[serde(default = "default_drop_existing_connections")]
    pub drop_existing_connections: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DynUpstreamConfig {
    /// The name
    pub name: String,
    /// The upstream address and port
    pub endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DynUserConfig {
    pub name: String,
    pub pass: String,
    pub upstream: Option<String>,
}

impl DynConf {
    /// Read the config from a TOML file
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        debug!(?path, "Loading dynamic config from file");
        let conf = read_toml(path)?;
        debug!(?path, "Dynamic config loaded successfully");
        Ok(conf)
    }

    /// Read the config from the path in `STATIC_CONF`
    pub fn load() -> Result<Self> {
        let path = &crate::STATIC_CONF.read().dyn_config_path;
        Self::load_from(path)
    }

    /// Write the config as a TOML file
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        debug!(?path, "Saving dynamic config to file");
        let data = toml::to_vec(self)?;
        let mut f = File::create(path)?;
        f.write_all(&data)?;
        debug!(?path, "Dynamic config saved successfully");
        Ok(())
    }

    /// Save the config to the path in `STATIC_CONF`
    pub fn save(&self) -> Result<()> {
        let path = &crate::STATIC_CONF.read().dyn_config_path;
        self.save_to(path)
    }
}

/// Needed by serde default
fn default_drop_existing_connections() -> bool {
    true
}

/// Custom serde implementation for `tracing::Level`
mod serde_opt_tracing_level {
    use std::str::FromStr;

    use serde::{de, Deserialize, Deserializer};
    use tracing::Level;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Level>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_s: Option<&str> = Option::deserialize(deserializer)?;
        let custom_err_wrapper = <D::Error as de::Error>::custom;
        opt_s
            .map(|s| Level::from_str(s).map_err(custom_err_wrapper))
            .transpose()
    }
}
