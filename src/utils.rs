use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

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

/// Lock type for read-biased `static` vars.
///
/// This implements an interface similar to `std::sync::RwLock`. The main
/// differences are: it can only be initialized once, and it must be initialized
/// before the first use.  It also doesn't deal at all with lock poisoning and
/// panics instead.
///
/// The main use case for this type is to wrap values that need to be `static`
/// and need to be writable (but rarely compared to the reads). The prime
/// example of this is a struct of configuration settings that can change at
/// runtime.
///
/// # Examples #
///
/// ```
/// static LOCK: OnceRwLock<String> = OnceRwLock::new();
///
/// fn main() {
///     LOCK.init("Hello".to_string());
///
///     // Use the value
///     println!("{}", *LOCK.read());
///
///     // Change the value
///     *LOCK.write() += " world!";
///     assert_eq!(LOCK.read().as_str(), "Hello world!");
/// }
/// ```
pub struct OnceRwLock<T> {
    inner: RwLock<Option<T>>,
}

impl<T> OnceRwLock<T> {
    /// Create a new empty OnceRwLock.
    pub const fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    /// Put a value into the OnceRwLock
    ///
    /// This method will panic if it is called more than once.
    pub fn init(&self, value: T) {
        let mut guard = self.inner.write().unwrap();
        if guard.is_some() {
            panic!("Cannot call OnceRWLock::init more than once");
        }
        guard.replace(value);
    }

    /// Obtain a read guard to access the underlying data
    pub fn read(&self) -> OnceRwLockReadGuard<T> {
        let guard = self.inner.read().unwrap();
        OnceRwLockReadGuard { inner: guard }
    }

    /// Obtain a write guard to access the underlying data
    pub fn write(&self) -> OnceRwLockWriteGuard<T> {
        let guard = self.inner.write().unwrap();
        OnceRwLockWriteGuard { inner: guard }
    }
}

pub struct OnceRwLockReadGuard<'a, T> {
    inner: RwLockReadGuard<'a, Option<T>>,
}

impl<'a, T> Deref for OnceRwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.deref().as_ref().unwrap()
    }
}

pub struct OnceRwLockWriteGuard<'a, T> {
    inner: RwLockWriteGuard<'a, Option<T>>,
}

impl<'a, T> Deref for OnceRwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.deref().as_ref().unwrap()
    }
}

impl<'a, T> DerefMut for OnceRwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.deref_mut().as_mut().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, BufStream};

    use super::*;

    use crate::pkts::AuthMethodProposal;

    #[test]
    fn test_static_once_rwlock() {
        static LOCK: OnceRwLock<String> = OnceRwLock::new();

        LOCK.init("Hello There!".to_string());
        assert_eq!(LOCK.read().as_str(), "Hello There!");

        *LOCK.write() = "Hola!".to_string();
        assert_eq!(LOCK.read().as_str(), "Hola!");
    }

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
