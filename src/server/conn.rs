use crate::{
    client::Client,
    pkts::{Command, Reply, ReplyCode, Request},
};
use tokio::task::JoinSet;

use super::*;

pub struct ConnManager<R: Router> {
    tasks: JoinSet<Result<()>>,
    router: R,
    // auth: A,
    cfg_notify_tx: watch::Sender<()>,
    cfg_notify_rx: watch::Receiver<()>,
}

impl<R: Router> ConnManager<R> {
    pub fn handle_connection(&mut self, tcpstream: TcpStream, client_sockaddr: SocketAddr) {
        let mut tcpstream = BufReader::new(tcpstream);

        let router = self.router.clone();
        let cfg_notify_rx = self.cfg_notify_rx.clone();
        self.tasks.spawn(async move {
            // choose auth method
            let auth_method = negotiate_auth_method(&mut tcpstream).await?;

            // only accept NO_AUTH for now
            assert_eq!(auth_method, AuthMethod::NO_AUTH);

            // From here on, the traffic can be wrapped depending on the auth method
            // Wait for a Request from the client
            // Also, there should be a Reply with an error code in case of errors.
            let request: Request = match recv_pkt(&mut tcpstream).await {
                Ok(req) => req,
                Err(e) => {
                    // TODO: not really this because if the request is malformed it's a client error
                    let reply: Reply = ReplyCode::ServerFailure.into();
                    send_pkt(&reply, &mut tcpstream).await?;
                    return Err(e.into());
                }
            };
            match request.command {
                Command::Connect => {
                    let target_addr = request.address;
                    let target_port = request.port;
                    let mut handler = ConnectHandler {
                        tcpstream,
                        client_sockaddr,
                        target_addr,
                        target_port,
                        router,
                        cfg_notify_rx,
                    };
                    handler.run().await
                }
                cmd => {
                    error!("Command {:?} is not implemented yet", cmd);
                    let reply: Reply = ReplyCode::CommandNotSUpported.into();
                    send_pkt(&reply, &mut tcpstream).await?;
                    Err(anyhow!("Command not supported"))
                }
            }
        });
    }
    // I still need a container for Conn data stuff: tcpstream, outer, sockaddr, extra stuff.
    // Use common + specific for each command type. Otherwise I have to carry a long list of args.
    // No state machine and everything private: only the ConnManager drives the conn.
}

async fn negotiate_auth_method(tcpstream: &mut BufTcpStream) -> Result<AuthMethod> {
    let authreq: AuthMethodProposal = recv_pkt(tcpstream).await?;
    debug!("Received AuthMethodProposal");
    // Here call the authenticator to choose the method
    // For now, only accept NO_AUTH
    match authreq
        .as_ref()
        .into_iter()
        .copied()
        .find(|am| *am == AuthMethod::NO_AUTH)
    {
        Some(am) => {
            debug!("Chose auth method {:?}", am);
            let auth_resp = AuthMethodResponse(Some(am));
            send_pkt(&auth_resp, tcpstream).await?;
            Ok(am)
        }
        None => {
            error!("No auth method acceptable");
            let abort_resp = AuthMethodResponse(None);
            send_pkt(&abort_resp, tcpstream).await?;
            Err(anyhow!(
                "No acceptable auth method. Proposed: {:?}",
                authreq
            ))
        }
    }
}

struct ConnectHandler<R: Router> {
    tcpstream: BufTcpStream,
    cfg_notify_rx: watch::Receiver<()>,
    target_addr: Address,
    target_port: u16,
    router: R,
    client_sockaddr: SocketAddr,
}

impl<R: Router> ConnectHandler<R> {
    /// Here the Reply has not been sent yet
    async fn run(&mut self) -> Result<()> {
        let (mut upstream_client, upstream_local_sockaddr) = match self.setup_upstream().await {
            Ok(ok) => ok,
            Err(e) => {
                // When Err in the request processing
                let reply: Reply = ReplyCode::ServerFailure.into();
                send_pkt(&reply, &mut self.tcpstream).await?;
                return Err(e.into());
            }
        };
        // Send the success reply
        let reply = Reply {
            code: ReplyCode::Success,
            address: upstream_local_sockaddr.ip().into(),
            port: upstream_local_sockaddr.port(),
        };
        send_pkt(&reply, &mut self.tcpstream).await?;

        // From now on, just copy from the client to upstream and reverse
        // Stop if there is a config change notification
        // Mark the cfg_notify as seen before starting
        self.cfg_notify_rx.borrow_and_update();
        let copy_fut = tokio::io::copy_bidirectional(&mut self.tcpstream, &mut upstream_client);
        tokio::pin!(copy_fut);
        loop {
            tokio::select! {
                res = self.cfg_notify_rx.changed() => {
                    res.unwrap();
                    // Recheck route
                    let new_upstream_sockaddr = self.router.route(self.client_sockaddr, &self.target_addr, self.target_port).await?;
                    if new_upstream_sockaddr != upstream_local_sockaddr {
                        return Err(anyhow!("Aborted on config change"));
                    } else {
                        debug!("Route unchanged");
                    }
                },
                res = &mut copy_fut => {
                    // Copy finished: both directions are closed
                    let (_, _) = res?;
                    return Ok(());
                }
            }
        }
    }

    /// Set up the upstream connection
    /// Errors here should be handled by (also) sending a Reply with an error ReplyCode.
    async fn setup_upstream(&mut self) -> Result<(Client<TcpStream>, SocketAddr)> {
        // Ask the router for the upstream proxy to use
        // The router could refuse: check the Err
        let upstream_sockaddr = self
            .router
            .route(self.client_sockaddr, &self.target_addr, self.target_port)
            .await?;

        // Try to connect to upstream (forward the target address & port)
        let upstream_tcpstream = TcpStream::connect(upstream_sockaddr).await?;
        let upstream_local_sockaddr = upstream_tcpstream.local_addr().unwrap();
        let upstream_client = client::make_client(
            upstream_tcpstream,
            self.target_addr.clone(),
            self.target_port,
        )
        .await?;

        Ok((upstream_client, upstream_local_sockaddr))
    }
}
