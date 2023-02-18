use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use crate::pkts::Address;
use conn::ConnManager;

/// Read-buffered TcpStream
type BufTcpStream = BufReader<TcpStream>;

mod conn;

#[async_trait]
pub trait Router: fmt::Debug + Clone + Send + Sync + 'static {
    /// Gives the addr&port for the upstream SOCKS proxy
    async fn route(
        &self,
        client_addr: SocketAddr,
        target_addr: &Address,
        target_port: u16,
    ) -> Result<SocketAddr>;
    // optional param: existing (upstream_addr, upstream_port) to aid in rerouting after config change.
}

pub trait ServerAuthenticator: fmt::Debug + Clone + Send + Sync + 'static {
    // async fn choose_auth_method(&self, &[AuthMethod]) -> Result<Box<dyn ServerAuthContext>>

    // For the ServerAuthContext:
    // async fn authenticate(&mut self, tcpstream: &mut BufTcpSTream, client addr/port) -> Result<()>
    // async fn wrap / unwrap
    // Accessors for the auth_data:
    // - client_addr/port
    // - user id (client identifier) can be username or something else (dns name/kerberos principal) so just an opaque byte string.
}

#[derive(Debug, Clone)]
pub struct SimpleRouter {
    fixed_upstream: SocketAddr,
}
impl SimpleRouter {
    pub async fn new<A: ToSocketAddrs>(addr: A) -> Result<Arc<RwLock<Self>>> {
        let fixed_upstream = tokio::net::lookup_host(addr)
            .await?
            .next()
            .ok_or(anyhow!("No address"))?;
        Ok(Arc::new(RwLock::new(Self { fixed_upstream })))
    }

    pub async fn replace_upstream<A: ToSocketAddrs>(&mut self, new: A) -> Result<SocketAddr> {
        let new = tokio::net::lookup_host(new)
            .await?
            .next()
            .ok_or(anyhow!("No address"))?;
        Ok(std::mem::replace(&mut self.fixed_upstream, new))
    }
}
#[async_trait]
impl Router for Arc<RwLock<SimpleRouter>> {
    async fn route(
        &self,
        _client_addr: SocketAddr,
        _target_addr: &Address,
        _target_port: u16,
    ) -> Result<SocketAddr> {
        let guard = self.read().await;
        Ok(guard.fixed_upstream.clone())
    }
}

#[derive(Debug, Clone)]
pub struct SimpleAuthenticator {}
impl ServerAuthenticator for SimpleAuthenticator {}

#[derive(Debug)]
pub struct Server<A: ServerAuthenticator, R: Router> {
    listener: TcpListener,
    /// This is unused for now
    authenticator: A,
    router: R,
    conn_mgr: ConnManager<R>,
}

impl<A: ServerAuthenticator, R: Router> Server<A, R> {
    pub async fn new<S: ToSocketAddrs>(
        listen_addr: S,
        router: R,
        authenticator: A,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        let conn_mgr = ConnManager::new(router.clone());
        Ok(Self {
            listener,
            authenticator,
            router,
            conn_mgr,
        })
    }
    fn listen_addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    #[tracing::instrument(skip(self))]
    /// Run the listener and the conn_manager in parallel
    pub async fn run(&mut self) -> Result<()> {
        info!(listen_addr=%self.listen_addr(), "Server is running");
        // Destructure to get a &mut to both
        let Self {
            listener, conn_mgr, ..
        } = self;

        loop {
            if conn_mgr.is_empty() {
                // Just accept a new connection
                let (tcpstream, client_sockaddr) = listener.accept().await?;
                debug!(%client_sockaddr, "New connection");
                conn_mgr.handle_connection(tcpstream, client_sockaddr);
            } else {
                // Run accept and conn_mgr.join concurrently
                tokio::select! {
                    res = listener.accept() => {
                        let (tcpstream, client_sockaddr) = res?;
                        debug!(%client_sockaddr, "New connection");
                        conn_mgr.handle_connection(tcpstream, client_sockaddr);
                    },
                    res = conn_mgr.join() => {
                        // Handle errors in join. What's left is propagated
                        res?;
                    }
                }
            }
        }
    }

    pub fn notify_config_change(&self) {
        self.conn_mgr.notify_config_change()
    }

    pub fn set_upstream_device(&mut self, value: Option<Vec<u8>>) {
        self.conn_mgr.set_upstream_device(value);
    }
}
