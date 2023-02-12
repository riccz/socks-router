use std::iter::successors;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::RecursiveMode;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info};
use tracing_subscriber::{filter, FmtSubscriber};

mod client;
mod config;
mod domain;
mod pkts;
mod server;
mod utils;
mod watcher;

use config::{parse_args_and_read_config, DynConf, StaticConf};
use server::{Server, SimpleAuthenticator, SimpleRouter};
use utils::OnceRwLock;
use watcher::AsyncWatcher;

static STATIC_CONF: OnceRwLock<StaticConf> = OnceRwLock::new();
static DYN_CONF: OnceRwLock<DynConf> = OnceRwLock::new();

/// This is just to format the errors
/// While letting the destructors run (close the sockets/files)
#[tokio::main]
async fn main() -> ExitCode {
    match inner_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}\n", e);

            for cause in successors(e.source(), |e| e.source()) {
                eprintln!("Caused by: {}", cause);
            }

            ExitCode::FAILURE
        }
    }
}

async fn inner_main() -> Result<()> {
    STATIC_CONF.init(parse_args_and_read_config()?);

    console_subscriber::init();
    // // a builder for `FmtSubscriber`.
    // let subscriber = FmtSubscriber::builder()
    //     // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
    //     // will be written to stdout.
    //     .with_max_level(Level::TRACE)
    //     // completes the builder.
    //     .finish();

    // tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Read initial dynamic config
    let dynconf_path = &STATIC_CONF.read().dyn_config_path;
    info!(?dynconf_path, "Using dynamic config at {:?}", dynconf_path);
    DYN_CONF.init(
        DynConf::load().with_context(|| format!("Invalid dynamic config {:?}", dynconf_path))?,
    );

    // Setup the server
    let router = SimpleRouter::new(&DYN_CONF.read().upstream_addr).await?;
    let authenticator = SimpleAuthenticator {};
    let mut server = Server::new(&STATIC_CONF.read().listen, router.clone(), authenticator).await?;

    let (watcher_handle, mut watcher_rx) = run_watcher(dynconf_path)?;

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
                let new_config = DynConf::load()?;
                if new_config != *DYN_CONF.read() {
                    *DYN_CONF.write()= new_config;
                }

                // Update the router
                router.write().await.replace_upstream(&DYN_CONF.read().upstream_addr).await?;

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
///
/// When the file changes, the `mpsc::Receiver` returned by this function gets a
/// new message.  The watcher runs forever, unless the task is cancelled via the
/// returned `JoinHandle`.
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
