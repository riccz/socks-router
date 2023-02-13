use std::iter::successors;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::RecursiveMode;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, debug_span, info, info_span, trace, Instrument};
use tracing_subscriber::FmtSubscriber;

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

    // Setup logging
    let format = tracing_subscriber::fmt::format();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(STATIC_CONF.read().log_level)
        .event_format(format)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

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

    // Setup the watcher task
    let watcher_span = debug_span!("watcher", path = ?dynconf_path);
    let (watcher_handle, mut watcher_rx) = watcher_span.in_scope(|| run_watcher(dynconf_path))?;

    loop {
        tokio::select! {
            res = server.run() => {
                // Server shut down
                res?;
                break
            }
            res = watcher_rx.recv() => {
                let _events = res.expect("The mpsc sender was dropped")?;

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
    async {
        watcher_handle.abort();
        if let Err(e) = watcher_handle.await {
            debug!(%e, "Stopped the watcher");
        }
    }
    .instrument(watcher_span)
    .await;

    Ok(())
}

/// Start the watcher task for the given path
///
/// When the file changes, the `mpsc::Receiver` returned by this function gets a
/// new message.  The watcher runs forever, unless the task is cancelled via the
/// returned `JoinHandle`.
///
/// The errors from the AsyncWatcher are passed into the channel and should be handled at the receiver side.
/// They can't accumulate with automatic retries, because the channel has capacity 1.
fn run_watcher<P: AsRef<Path>>(
    watch_path: P,
) -> Result<(
    JoinHandle<Result<()>>,
    mpsc::Receiver<Result<Vec<notify::Event>, notify::Error>>,
)> {
    // Watch the parent directory and filter on the path, because some editors
    // (e.g. vim) rename the original to backup and replace with a new file.
    // FIXME: check the event type  and unwatch/watch the new file
    let watch_path = watch_path.as_ref().canonicalize()?;
    let parent_dir = watch_path.parent().unwrap();
    debug!(?parent_dir, "Watching parent dir");

    let mut watcher = AsyncWatcher::new()?;
    watcher.watch(parent_dir, RecursiveMode::Recursive)?;

    // Capacity 1 is important for errors: avoid retrying in the loop and accumulating more than one error.
    let (tx, rx) = mpsc::channel(1);
    let handle = tokio::spawn(
        async move {
            debug!("Starting watcher task");
            // This never exits: errors are passed into the mpsc channel
            // The only wait to stop this is to abort the task via the JoinHandle
            loop {
                let res_events = watcher
                    .next_debounced_filter(Duration::from_millis(500), |e| {
                        e.paths.contains(&watch_path)
                    })
                    .await;
                match res_events {
                    Ok(events) => {
                        let event_count = events.len();
                        assert!(event_count > 0);
                        debug!(?event_count, "Watcher saw at least one event");
                        tx.send(Ok(events))
                            .await
                            .expect("The mpsc receiver was dropped");
                    }
                    Err(e) => {
                        trace!(%e, "Error while watching for file changes");
                        tx.send(Err(e))
                            .await
                            .expect("The mpsc receiver was dropped");
                    }
                }
            }
        }
        .in_current_span(),
    );
    Ok((handle, rx))
}
