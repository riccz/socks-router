use std::iter::successors;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use notify::RecursiveMode;
use serde::{Deserialize, Serialize};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, debug_span, error, info, info_span, trace, Instrument};
use tracing_subscriber::FmtSubscriber;
use warp::{filters, path, Filter};

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
    let router = SimpleRouter::new(get_default_upstream()?).await?;
    let authenticator = SimpleAuthenticator {};
    let mut server = Server::new(&STATIC_CONF.read().listen, router.clone(), authenticator).await?;
    if let Some(ud) = &STATIC_CONF.read().upstream_device {
        server.set_upstream_device(Some(ud.as_bytes().to_owned()));
    }

    // Setup the watcher task
    let watcher_span = debug_span!("watcher", path = ?dynconf_path);
    let (watcher_handle, mut watcher_rx) = watcher_span.in_scope(|| run_watcher(dynconf_path))?;

    // warp task
    let api_listen = STATIC_CONF.read().api_listen.clone();
    let warp_span = debug_span!("warp", ?api_listen); // Redundant? Server::run already creates a span
    let warp_handle = tokio::spawn(
        async move {
            let patch_default_settings_route = path!("default")
                .and(filters::method::patch())
                .and(filters::body::json())
                .and_then(handle_patch_defaults);

            let get_default_settings_route = path!("default")
                .and(filters::method::get())
                .map(|| warp::reply::json(&DYN_CONF.read().default));

            let get_upstreams_route = path!("upstreams")
                .and(filters::method::get())
                .map(|| warp::reply::json(&DYN_CONF.read().upstreams)); // FIXME: everything, really?

            let api_route = filters::path::path("api").and(
                patch_default_settings_route
                    .or(get_default_settings_route)
                    .or(get_upstreams_route),
            );

            info!("Starting warp API server");
            let server = warp::serve(api_route);
            let sockaddr: SocketAddr = api_listen.parse()?;
            server.run(sockaddr).await;

            Result::<()>::Ok(())
        }
        .instrument(warp_span.clone()),
    );

    // Listen for Ctrl-C
    let ctrl_c_fut = signal::ctrl_c();
    tokio::pin!(ctrl_c_fut);

    loop {
        tokio::select! {
            res = &mut ctrl_c_fut => {
                res?;
                info!("Received Ctrl-C, shutting down");
                // If Ctrl-C again quit immediately
                tokio::spawn(async move {
                    signal::ctrl_c().await.expect("Failed to listen for Ctrl-C");
                    error!("Received Ctrl-C again, force quit now");
                    std::process::exit(1);
                });
                break;
            }
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
                router.write().await.replace_upstream(get_default_upstream()?).await?;

                // Notify new config to the server
                server.notify_config_change();
            }
        }
    }

    // Shutdown warp
    async {
        warp_handle.abort();
        if let Err(e) = warp_handle.await {
            debug!(%e, "Stopped Warp");
        }
    }
    .instrument(warp_span)
    .await;

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

// Payload of PATCH /api/default
#[derive(Debug, Serialize, Deserialize)]
struct PatchDefaultPayload {
    pub upstream: Option<String>,
}

async fn handle_patch_defaults(
    payload: PatchDefaultPayload,
) -> Result<impl warp::Reply, warp::Rejection> {
    if let Some(upstream) = payload.upstream {
        debug!(?upstream, "Got an upstream PATCH request");

        let mut guard = DYN_CONF.write();
        if guard.default.upstream != upstream {
            // Check that it actually exists
            if guard
                .upstreams
                .iter()
                .find(|u| u.name == upstream)
                .is_none()
            {
                return Err(warp::reject()); // actually should be 400
            }

            guard.default.upstream = upstream;
            if let Err(e) = guard.save() {
                error!(%e, "Failed to write the dynamic conf file");
                return Err(warp::reject()); // Actually should be 500
            }
        }
    } else {
        // Empty
        return Err(warp::reject::reject()); // Actually should be a 400
    }

    // Default is empty OK
    Ok(warp::reply::reply())
}

fn get_default_upstream() -> Result<String> {
    let guard = DYN_CONF.read();
    Ok(guard
        .upstreams
        .iter()
        .find(|u| u.name == guard.default.upstream)
        .ok_or(anyhow!("Invalid upstream: {:?}", guard.default.upstream))?
        .endpoint
        .clone())
}
