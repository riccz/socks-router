use std::borrow::Borrow;
use std::cmp::max;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project::pin_project;
use tokio::io::{split, AsyncBufRead, AsyncRead, AsyncWrite, BufReader, ReadBuf};

use anyhow::{anyhow, Result};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::pkts::{Address, AuthMethod, AuthMethodProposal, AuthMethodResponse, Reply, Request};
use crate::utils::{read_pkt, send_pkt};

// Since I have the leftovers, I need to adapt the AsyncRead interface
#[pin_project]
pub struct Client<S: AsyncRead + AsyncWrite> {
    #[pin]
    stream: S,
    /// Data left over from the buffered reader used during SOCKS session setup.
    /// Should be None almost always. This is necessary in case the SOCKS server sends proxied data immediately after its last reply.
    leftovers: Option<Vec<u8>>,
    /// The source address used by the proxy to reach the target (as received in the Reply)
    proxy_src_addr: Address,
    /// The source port used by the proxy to reach the target (as received in the Reply)
    proxy_src_port: u16,
}

pub async fn make_tcp_connect_client<A: ToSocketAddrs>(
    server_addr: A,
    target_addr: Address,
    target_port: u16,
) -> Result<Client<TcpStream>> {
    let tcpstream = TcpStream::connect(server_addr).await?;
    make_client(tcpstream, target_addr, target_port).await
}

// This is for a connect client
pub async fn make_client<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    addr: Address,
    port: u16,
) -> Result<Client<S>> {
    // Buffer the reader
    let (reader, mut writer) = split(stream);
    let mut reader = BufReader::new(reader);

    // common: authentication
    let methods = vec![AuthMethod::NO_AUTH];
    let accepted_method = negotiate_auth_method(&mut reader, &mut writer, &methods).await?;
    assert_eq!(accepted_method, AuthMethod::NO_AUTH);

    // different for each command: request
    // just connect for now
    let (proxy_src_addr, proxy_src_port) = connect(&mut reader, &mut writer, addr, port).await?;

    // Unwrap the buffered reader and rejoin into a stream
    // Keep the unread buffer from the BufReader
    let leftovers = if reader.buffer().len() > 0 {
        let mut v = Vec::with_capacity(reader.buffer().len());
        v.extend_from_slice(reader.buffer());
        Some(v)
    } else {
        None
    };
    let reader = reader.into_inner();
    let stream = reader.unsplit(writer);

    Ok(Client {
        stream,
        leftovers,
        proxy_src_addr,
        proxy_src_port,
    })
}

// First consume the leftovers, then proxy to the inner stream.
impl<S: AsyncRead + AsyncWrite> AsyncRead for Client<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        match this.leftovers {
            None => AsyncRead::poll_read(this.stream, cx, buf),
            Some(leftovers) => {
                assert!(leftovers.len() > 0);
                let n = max(leftovers.len(), buf.remaining());
                buf.put_slice(&leftovers[..n]);

                if n == leftovers.len() {
                    this.leftovers.take();
                } else {
                    let mut new = leftovers.split_off(n);
                    std::mem::swap(&mut new, leftovers);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

// Just proxy everthing to the inner stream
impl<S: AsyncRead + AsyncWrite> AsyncWrite for Client<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(self.project().stream, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(self.project().stream, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(self.project().stream, cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write_vectored(self.project().stream, cx, bufs)
    }
}

/// Run the authentication negotiation
///
/// Returrns OK only if the server accepts one of the proposed auth methods
async fn negotiate_auth_method<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    methods: &[AuthMethod],
) -> Result<AuthMethod> {
    let authmethod_proposal = AuthMethodProposal::from_slice(methods)?;
    send_pkt(&authmethod_proposal, writer).await?;

    let auth_response: AuthMethodResponse = read_pkt(reader).await?;
    match auth_response.0 {
        Some(am) if methods.contains(&am) => Ok(am),
        Some(am) => Err(anyhow!(
            "Accepted a mathod that was not requested: {:?}",
            am
        )),
        None => Err(anyhow!("No method accepted")),
    }
}

/// Send a connect request
///
/// After this is successful, you can send/receive from the stream
/// Returns the address & port from the Reply
async fn connect<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin, A: Borrow<Address>>(
    reader: &mut R,
    writer: &mut W,
    addr: A,
    port: u16,
) -> Result<(Address, u16)> {
    let request = Request::connect(addr.borrow().clone(), port);
    send_pkt(&request, writer).await?;

    let reply: Reply = read_pkt(reader).await?;
    if !reply.is_success() {
        Err(anyhow!("Connect request failed: {:?}", reply.code))
    } else {
        Ok((reply.address, reply.port))
    }
}
