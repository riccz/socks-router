use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use clap::Parser;
use lazy_static::lazy_static;
use notify::RecursiveMode;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, Level};
use tracing_subscriber::{filter, FmtSubscriber};

mod client;
mod config;
mod domain;
mod pkts;
mod server;
mod utils;
mod watcher;

use crate::config::{DynConf, StaticConf};
use server::{Server, SimpleAuthenticator, SimpleRouter};
use watcher::AsyncWatcher;

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = StaticConf::parse();

    console_subscriber::init();
    // // a builder for `FmtSubscriber`.
    // let subscriber = FmtSubscriber::builder()
    //     // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
    //     // will be written to stdout.
    //     .with_max_level(Level::TRACE)
    //     // completes the builder.
    //     .finish();

    // tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    // let conf_path = confy::get_configuration_file_path("socks_router", "config")?;

    info!("Loading config from {:?}", cli_args.config_path);
    let mut dynconf = DynConf::load(&cli_args.config_path)?;

    let router = SimpleRouter::new(&dynconf.upstream_addr).await?;
    let authenticator = SimpleAuthenticator {};
    let mut server = Server::new(&cli_args.listen_addr, router.clone(), authenticator).await?;

    let (watcher_handle, mut watcher_rx) = run_watcher(&cli_args.config_path)?;

    loop {
        tokio::select! {
            res = server.run() => {
                // Server shut down
                res?;
                break
            }
            res = watcher_rx.recv() => {
                res.expect("Dropped the sender"); // This happens when the watcher task errors
                // Reread the config
                dynconf = DynConf::load(&cli_args.config_path)?;
                router.write().await.replace_upstream(&dynconf.upstream_addr).await?;

                // Notify new config to the server
                server.notify_config_change();
            }
        }
    }

    // Shutdown the watcher
    watcher_handle.abort();
    if let Err(e) = watcher_handle.await {
        debug!("Aborted the watcher with {}", e);
    }

    Ok(())
}

/// Start the watcher task for the given path
fn run_watcher<P: AsRef<Path>>(
    watch_path: P,
) -> Result<(JoinHandle<Result<()>>, mpsc::Receiver<()>)> {
    // Watch the parent directory and filter on the path, because some editors
    // (e.g. vim) rename the original to backup and replace with a new file.
    // FIXME: check the event type  and unwatch/watch the new file
    let watch_path = watch_path.as_ref().canonicalize()?;
    let parent_dir = watch_path.parent().unwrap();

    let mut watcher = AsyncWatcher::new()?;
    watcher.watch(parent_dir, RecursiveMode::Recursive)?;

    let (tx, rx) = mpsc::channel(1);
    let handle = tokio::spawn(async move {
        loop {
            let events = watcher
                .next_debounced_filter(Duration::from_millis(500), |e| {
                    e.paths.contains(&watch_path)
                })
                .await?;
            if events.len() > 0 {
                tx.send(()).await.expect("Dropped the receiver");
            }
        }
    });
    Ok((handle, rx))
}
