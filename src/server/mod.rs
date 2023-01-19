use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Buf;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, BufReader};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::client;
use crate::pkts::{Address, AuthMethod, AuthMethodProposal, AuthMethodResponse};
use crate::utils::{recv_pkt, send_pkt};

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
struct SimpleRouter {
    fixed_upstream: SocketAddr,
}
impl SimpleRouter {
    pub async fn new<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let fixed_upstream = tokio::net::lookup_host(addr)
            .await?
            .next()
            .ok_or(anyhow!("No address"))?;
        Ok(Self { fixed_upstream })
    }
}
#[async_trait]
impl Router for SimpleRouter {
    async fn route(
        &self,
        _client_addr: SocketAddr,
        _target_addr: &Address,
        _target_port: u16,
    ) -> Result<SocketAddr> {
        Ok(self.fixed_upstream.clone())
    }
}

#[derive(Debug, Clone)]
struct SimpleAuthenticator {}
impl ServerAuthenticator for SimpleAuthenticator {}

#[derive(Debug)]
pub struct Server<A: ServerAuthenticator, R: Router> {
    listener: TcpListener,
    authenticator: Arc<RwLock<A>>,
    router: Arc<RwLock<R>>,
    conn_tasks: Vec<JoinHandle<Result<()>>>,
    config_changed_chan: (watch::Sender<()>, watch::Receiver<()>),
}

impl<A: ServerAuthenticator, R: Router> Drop for Server<A, R> {
    #[tracing::instrument]
    fn drop(&mut self) {
        let force_close_count = self.conn_tasks.len();
        info!(
            force_close_count,
            "Force close {} connections", force_close_count,
        );
        for handle in self.conn_tasks.iter() {
            handle.abort();
        }
    }
}

impl Server<SimpleAuthenticator, SimpleRouter> {
    pub async fn new<SA: ToSocketAddrs>(addr: SA) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        // Default NO_AUTH for now
        let authenticator = Arc::new(RwLock::new(SimpleAuthenticator {}));
        let router = Arc::new(RwLock::new(SimpleRouter::new("127.0.0.1:1090").await?));
        Ok(Self {
            listener,
            authenticator,
            router,
            conn_tasks: vec![],
            config_changed_chan: watch::channel(()),
        })
    }
}

impl<A: ServerAuthenticator, R: Router> Server<A, R> {
    /// Accept a single client connection
    /// The client connection is driven by a separate tokio::task
    #[tracing::instrument]
    async fn accept(&mut self) -> Result<()> {
        let (tcpstream, client_addr) = self.listener.accept().await?;
        eprintln!("New connection from {:?}", client_addr);
        let tcpstream = BufReader::new(tcpstream);
        // let mut conn = Connection {
        //     tcpstream,
        //     router: self.router.clone(),
        //     authenticator: self.authenticator.clone(),
        //     auth_context: None,
        // };

        let mut confchange_rx = self.config_changed_chan.1.clone();
        let handle = tokio::spawn(async move {
            // tokio::pin!(conn);
            // tokio::pin!(confchange_rx);
            tokio::select! {
                // res = conn.run() => {
                //     return res;
                // }
                _ = confchange_rx.changed() => {
                    debug!("Config changed: abort");
                    return Err(anyhow!("Conf changed: abort"));
                }
            }
        });
        self.conn_tasks.push(handle);

        Ok(())
    }

    pub async fn listen(&mut self) -> Result<()> {
        eprintln!("Listen on {:?}", self.listener.local_addr().unwrap());
        loop {
            self.accept().await?;
        }
    }

    pub fn notify_config_change(&mut self) {
        self.config_changed_chan.0.send(()).unwrap();
    }
}

/// Server connection before authentication
struct UnauthConn<R: Router> {
    tcpstream: BufTcpStream,
    /// This is only carried for the conversion into Connection.
    /// The UnauthConn doesn't do anything with the router.
    router: R,
    // The server authenticator
    // server_auth: A
}

impl<R: Router> UnauthConn<R> {
    async fn authenticate(self) -> Result<Connection<R>> {
        // No authentication yet, just confirm NO_AUTH

        Ok(Connection {
            tcpstream: self.tcpstream,
            router: self.router,
        })
    }
}

struct Connection<R: Router> {
    tcpstream: BufTcpStream,
    router: R,
    // authenticator: Arc<RwLock<A>>,
    // auth_context: Option<AuthContext>,
}

impl<R: Router> Connection<R> {
    pub async fn run(&mut self) -> Result<()> {
        loop {
            let mut buf = vec![0; 4096];
            let n = self.tcpstream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }
}

struct AuthContext {}

// // There is only one of these per-server, so it can be complex
// // All clients of the same server will use the same authenticator
// struct ServerAuthenticator {}

// impl ServerAuthenticator {
//     /// Choose an auth method from the acceptable ones
//     pub fn choose_method(
//         &self,
//         client_addr: &SocketAddr,
//         client_proposed: &[AuthMethod],
//     ) -> Option<AuthMethod> {
//         if client_proposed.contains(&AuthMethod::NO_AUTH) {
//             Some(AuthMethod::NO_AUTH)
//         } else {
//             None
//         }
//     }
// }

// AuthContext : per-connection, after choosing the auth method, is stateful (case of GSS), can wrap/unwrap the data.

// struct ServerConnection<'a> {
//     tcpstream: BufReader<TcpStream>,
//     client_addr: SocketAddr,
//     authenticator: &'a ServerAuthenticator,
// }

// impl<'a> ServerConnection<'a> {
//     pub async fn handle_connection(&mut self) -> Result<()> {
//         let auth_method = self.negotiate_auth_method().await?;
//         // Here run the auth method: get an AuthContext

//         Ok(())
//     }

//     /// Run the auth method negotiation
//     /// After this method returns Ok, the specific authentication method can run.
//     async fn negotiate_auth_method(&mut self) -> Result<AuthMethod> {
//         let authreq: AuthMethodProposal = read_pkt(&mut self.tcpstream).await?;
//         eprintln!("Received AuthMethodProposal");
//         match self
//             .authenticator
//             .choose_method(&self.client_addr, authreq.as_ref())
//         {
//             Some(am) => {
//                 eprintln!("Chose method {:?}", am);
//                 let auth_resp = AuthMethodResponse(Some(am));
//                 send_pkt(&auth_resp, &mut self.tcpstream).await?;
//                 Ok(am)
//             }
//             None => {
//                 eprintln!("No auth method acceptable");
//                 let abort_resp = AuthMethodResponse(None);
//                 send_pkt(&abort_resp, &mut self.tcpstream).await?;
//                 Err(anyhow!(
//                     "No acceptable auth method. Proposed: {:?}",
//                     authreq
//                 ))
//             }
//         }
//     }
// }

// /// Pre-authentication connection
// struct NewConn {
//     tcpstream: BufTcpStream,
//     client_addr: SocketAddr,
// }
