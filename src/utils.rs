use std::io;

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};

use anyhow::{anyhow, Result};

use crate::pkts::Packet;

/// Read a packet of the given type from the reader.
/// This function keeps filling the reader's buffer until a full packet can be parsed or there is an error.
/// The reader's buffer only gets consumed if the packet parsing is successful.
// Errors can be std::io::Error (from reading) or nom::Err (from parsing)
pub async fn recv_pkt<P: Packet, R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<P> {
    loop {
        let rdbuf = reader.fill_buf().await?;
        if rdbuf.len() < 1 {
            let kind = std::io::ErrorKind::UnexpectedEof;
            let e = std::io::Error::new(kind, anyhow!("EOF while reading a packet"));
            return Err(e.into()); //Err(anyhow!("EOF while reading a packet"));
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

/// Receive a Packet from the given AsyncRead reader.
/// Use the given buffer to store incomplete data.
/// The return value for Ok contains the parsed packet and the leftover data read from the reader.
#[allow(dead_code)]
pub async fn recv_pkt_buf<'a, P: Packet, R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &'a mut [u8],
) -> Result<(&'a [u8], P)> {
    let mut filled = 0;
    let packet = loop {
        if filled >= buf.len() {
            panic!("buffer is full and no complete packet")
        }

        // Read into the buffer, past the filled portion
        let n = reader.read(&mut buf[filled..]).await?;
        filled += n;

        if n == 0 {
            panic!("EOF and no complete packet");
        }

        match P::parse(&buf[..filled]) {
            // Cannot return `rest` directly, because then
            // the borrow in `parse` needs lifetime 'a,
            // which conflicts with the mut borrow in `read`.
            Ok((_rest, packet)) => break packet,
            Err(nom::Err::Incomplete(_)) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    // Manually rebuild `rest`: the packet length is known now,
    // take from after the packet until the filled portion.
    let rest = &buf[packet.pack_len()..filled];
    Ok((rest, packet))
}

/// Send a packet to the given AsyncWrite, using the given buffer as temp space
/// Errors: PackError or io::Error
pub async fn send_pkt_buf<P: Packet, W: AsyncWrite + Unpin>(
    packet: &P,
    writer: &mut W,
    buf: &mut [u8],
) -> Result<()> {
    let pkt_buf = packet.pack(buf)?;
    writer.write_all(pkt_buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Send a Packet to the given AsyncWrite, using a temp buffer
pub async fn send_pkt<P: Packet, W: AsyncWrite + Unpin>(
    packet: &P,
    writer: &mut W,
) -> Result<(), io::Error> {
    let mut buf = vec![0; packet.pack_len()];
    send_pkt_buf(packet, writer, &mut buf)
        .await
        .map_err(|e| match e.downcast::<io::Error>() {
            Ok(e) => e,
            Err(e) => panic!("Not io::Error: {}", e),
        })
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, BufStream};

    use super::*;

    use crate::pkts::AuthMethodProposal;

    #[tokio::test]
    async fn test_send_pkt() {
        let (mut local, mut remote) = duplex(4096);

        let p = AuthMethodProposal::default();
        send_pkt(&p, &mut local).await.unwrap();

        let mut rdbuf = vec![0; p.pack_len() + 1];
        let n = remote.read(&mut rdbuf).await.unwrap();
        assert_eq!(n, p.pack_len());
        let (_, rdp) = AuthMethodProposal::parse(&rdbuf).unwrap();
        assert_eq!(rdp, p);
    }

    #[tokio::test]
    async fn test_recv_pkt() {
        let (local, mut remote) = duplex(4096);

        let data = hex::decode("050100").unwrap();
        let n = remote.write(&data).await.unwrap();
        assert_eq!(n, data.len());

        let mut buflocal = BufStream::new(local);

        let p: AuthMethodProposal = recv_pkt(&mut buflocal).await.unwrap();
        assert_eq!(p, AuthMethodProposal::default());
        drop(remote);
        let mut buf = vec![0; 10];
        let n = buflocal.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_recv_pkt_buf() {
        let (mut local, mut remote) = duplex(4096);

        let data = hex::decode("050100").unwrap();
        let n = remote.write(&data).await.unwrap();
        assert_eq!(n, data.len());

        let mut buf = vec![0; 100];
        let (leftover, p) = recv_pkt_buf::<AuthMethodProposal, _>(&mut local, &mut buf)
            .await
            .unwrap();
        assert_eq!(p, AuthMethodProposal::default());
        assert_eq!(leftover.len(), 0);
        drop(remote);
        let n = local.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }
}
