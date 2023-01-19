use std::io::BufRead;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader, BufStream,
};
use tokio::{io::AsyncWriteExt, net::TcpListener, net::TcpStream};

use anyhow::{anyhow, Result};

use pkts::Packet;

mod client;
mod domain;
mod pkts;
mod server;
mod utils;

use client::{make_client, make_tcp_connect_client, Client};
use pkts::Address;

use server::Server;

use tracing::{debug, info, Level};
use tracing_subscriber::FmtSubscriber;

async fn router_main() -> Result<()> {
    listen_server().await?;
    Ok(())
}

#[tracing::instrument]
async fn my_logging_func() {
    debug!("Inside the func");
}

#[tokio::main]
async fn main() -> Result<()> {
    console_subscriber::init();
    // // a builder for `FmtSubscriber`.
    // let subscriber = FmtSubscriber::builder()
    //     // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
    //     // will be written to stdout.
    //     .with_max_level(Level::TRACE)
    //     // completes the builder.
    //     .finish();

    // tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting");

    my_logging_func().await;

    router_main().await?;
    Ok(())
}

/// Read a packet of the given type from the reader.
/// This function keeps filling the reader's buffer until a full packet can be parsed or there is an error.
/// The reader's buffer only gets consumed if the packet parsing is successful.
async fn read_pkt<P: Packet, R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<P> {
    loop {
        let rdbuf = reader.fill_buf().await?;
        if (rdbuf.len() < 1) {
            return Err(anyhow!("EOF"));
        }

        match P::parse(rdbuf) {
            Ok((rest, response)) => {
                let consumed = rdbuf.len() - rest.len();
                reader.consume(consumed);
                return Ok(response);
            }
            Err(nom::Err::Incomplete(_)) => continue,
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}

async fn send_pkt_buf<P: Packet, W: AsyncWrite + Unpin>(
    packet: &P,
    writer: &mut W,
    buf: &mut [u8],
) -> Result<()> {
    let pkt_buf = packet.pack(buf)?;
    writer.write_all(pkt_buf).await?;
    writer.flush().await?;
    Ok(())
}

async fn send_pkt<P: Packet, W: AsyncWrite + Unpin>(packet: &P, writer: &mut W) -> Result<()> {
    let mut buf = vec![0; packet.pack_len()];
    send_pkt_buf(packet, writer, &mut buf).await
}

async fn handle_connection(socket: TcpStream, remote: SocketAddr) -> Result<()> {
    eprintln!("New connection from {:?}", remote);

    let mut tcpstream = BufReader::new(socket);

    // Pick the authmethod
    let authreq: pkts::AuthMethodProposal = read_pkt(&mut tcpstream).await?;
    if authreq
        .as_ref()
        .into_iter()
        .find(|am| **am == pkts::AuthMethod::NO_AUTH)
        .is_none()
    {
        eprintln!("NoAuth not requested");
        let abort_resp = pkts::AuthMethodResponse(None);
        send_pkt(&abort_resp, &mut tcpstream).await?;
        eprintln!("Abort connection from {:?}", remote);
        return Ok(());
    }
    eprintln!("NoAuth is OK");
    let auth_resp = pkts::AuthMethodResponse(Some(pkts::AuthMethod::NO_AUTH));
    send_pkt(&auth_resp, &mut tcpstream).await?;

    // NoAuth doesn't do anything

    // Wait for a command request
    let cmd_req: pkts::Request = read_pkt(&mut tcpstream).await?;
    match cmd_req.command {
        pkts::Command::Connect => {
            eprintln!(
                "{:?} requested connect to {:?} port {}",
                remote, cmd_req.address, cmd_req.port
            );
            handle_connect_request(&mut tcpstream, cmd_req).await?;
        }
        _ => {
            eprintln!("Only Connect is supported ATM");
            return Ok(());
        }
    }

    eprintln!("Close connection from {:?}", remote);
    Ok(())
}

async fn handle_connect_request(
    mut tcpstream: &mut BufReader<TcpStream>,
    cmd_req: pkts::Request,
) -> Result<()> {
    assert_eq!(cmd_req.command, pkts::Command::Connect);

    let upstream = "127.0.0.1:1090";
    // Open the SOCKS session with the upstream server
    let mut upstream_client =
        make_tcp_connect_client(upstream, cmd_req.address, cmd_req.port).await?;

    // Proxy connection is OK, reply and then start proxying
    // I should get the actual address/port from the upstream reply
    // Also, I should proxy the error code too
    let ok_reply = pkts::Reply {
        address: pkts::Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
        port: 0,
        code: pkts::ReplyCode::Success,
    };
    send_pkt(&ok_reply, &mut tcpstream).await?;

    // Proxy all the connection
    let (tot_up, tot_down) =
        tokio::io::copy_bidirectional(&mut tcpstream, &mut upstream_client).await?;

    eprintln!(
        "TCP Proxy connection closed: sent {} byte upstream, received {} bytes",
        tot_up, tot_down
    );

    Ok(())
}

#[tracing::instrument]
async fn listen_server() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:1080").await?;

    loop {
        eprintln!("Wait for connection");
        let (socket, remote) = listener.accept().await?;
        let _handle = tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, remote).await {
                eprintln!("Error handling connection: {}", e);
            }
        });
        // Don't await the handle here, otherwise no parallel connection handling
    }
}
