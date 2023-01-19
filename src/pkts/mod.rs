use std::{
    borrow::Borrow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use thiserror::Error;

use crate::domain::{DomainName, DomainNameError};

mod parse;

pub use parse::IResult;

// This is used in helper functions that use pack/parse
pub trait Packet: Sized {
    fn parse(input: &[u8]) -> parse::IResult<&[u8], Self>;
    fn pack_len(&self) -> usize;
    fn pack<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], PackError>;
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("buffer is too short {got} ({need} needed)")]
    BufferTooShort { need: usize, got: usize },
}

#[derive(Debug, Error)]
pub enum AuthMethodProposalError {
    #[error("duplicate auth method: {0:?}")]
    DuplicateMethod(AuthMethod),
    #[error("cannot add auth method {0:?} (max number is 253)")]
    TooManyMethods(AuthMethod),
}

/// Value of the `version` field of SOCKS5 packets.
const VERSION: u8 = 0x05;

/// Authentication Method
///
/// Guaranteed to never be 0xff.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AuthMethod(u8);

impl AuthMethod {
    pub const NO_AUTH: Self = Self(0x00);
    #[allow(dead_code)]
    pub const GSS_API: Self = Self(0x01);
    #[allow(dead_code)]
    pub const USER_PASS: Self = Self(0x02);

    /// Raw value of "no method acceptable".
    ///
    /// This is only used in the response
    const RAW_NONE: u8 = 0xff;

    /// Convert from a raw byte.
    ///
    /// If the value is 0xff (no method acceptable), return None.
    pub fn new(raw: u8) -> Option<Self> {
        if raw == Self::RAW_NONE {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

// max 255 bytes total for pkt (everything except NoneAcceptable). Max length of method: 253
// Cannot expose directly the inner vector because the AuthMethods must be unique and max 253
#[derive(Debug, PartialEq, Eq)]
pub struct AuthMethodProposal(Vec<AuthMethod>);

impl AuthMethodProposal {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn add(&mut self, method: AuthMethod) -> Result<(), AuthMethodProposalError> {
        if self.0.len() + 1 > 253 {
            // keep the total packet length < 255 (-2bytes for the version and vec length)
            Err(AuthMethodProposalError::TooManyMethods(method))
        } else if self.0.contains(&method) {
            Err(AuthMethodProposalError::DuplicateMethod(method))
        } else {
            self.0.push(method);
            Ok(())
        }
    }

    pub fn from_slice(auth_methods: &[AuthMethod]) -> Result<Self, AuthMethodProposalError> {
        let mut amp = Self(Vec::with_capacity(auth_methods.len()));
        for am in auth_methods {
            amp.add(*am)?
        }
        Ok(amp)
    }
}
impl Packet for AuthMethodProposal {
    fn parse(input: &[u8]) -> parse::IResult<&[u8], Self> {
        parse::auth_method_proposal(input)
    }

    fn pack_len(&self) -> usize {
        self.0.len() + 2
    }

    fn pack<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], PackError> {
        let min_len = self.pack_len();
        if output.len() < min_len {
            return Err(PackError::BufferTooShort {
                need: min_len,
                got: output.len(),
            });
        }

        output[0] = VERSION;
        output[1] = self.0.len() as u8;
        for (am, out) in self.0.iter().zip(output[2..].iter_mut()) {
            *out = am.0;
        }

        Ok(&output[..min_len])
    }
}

impl Default for AuthMethodProposal {
    fn default() -> Self {
        AuthMethodProposal(vec![AuthMethod::NO_AUTH])
    }
}

impl AsRef<Vec<AuthMethod>> for AuthMethodProposal {
    fn as_ref(&self) -> &Vec<AuthMethod> {
        &self.0
    }
}

// All possible values for Option<AuthMethod> are valid
pub struct AuthMethodResponse(pub Option<AuthMethod>);

impl Packet for AuthMethodResponse {
    fn parse(input: &[u8]) -> parse::IResult<&[u8], Self> {
        parse::auth_method_response(input)
    }

    fn pack_len(&self) -> usize {
        2
    }

    fn pack<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], PackError> {
        buf[0] = VERSION;
        buf[1] = match &self.0 {
            Some(method) => method.0,
            None => 0xff,
        };
        Ok(&buf[..2])
    }
}

/// Address type used in SOCKS5 packets
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(DomainName),
}

impl Address {
    const IPV4_TAG: u8 = 0x01;
    const IPV6_TAG: u8 = 0x04;
    const DOMAIN_TAG: u8 = 0x03;

    pub fn pack_len(&self) -> usize {
        // 1-byte type tag + each type representation
        1 + match self {
            Address::Ipv4(_) => 4,
            Address::Ipv6(_) => 16,
            Address::Domain(s) => 1 + s.dot_len(), // 1-byte length + content
        }
    }

    pub fn pack<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], PackError> {
        if buf.len() < self.pack_len() {
            return Err(PackError::BufferTooShort {
                need: self.pack_len(),
                got: buf.len(),
            });
        }

        match self {
            Address::Ipv4(ipv4) => {
                buf[0] = Self::IPV4_TAG;
                buf[1..5].clone_from_slice(ipv4.octets().as_slice());
            }
            Address::Ipv6(ipv6) => {
                buf[0] = Self::IPV6_TAG;
                buf[1..17].clone_from_slice(ipv6.octets().as_slice());
            }
            Address::Domain(domain) => {
                buf[0] = Self::DOMAIN_TAG;
                let n = domain.dot_len();
                assert!(n <= 255);
                buf[1] = n as u8;
                buf[2..2 + n].clone_from_slice(domain.as_ref().as_bytes())
            }
        }

        Ok(&buf[..self.pack_len()])
    }
}

impl std::string::ToString for Address {
    fn to_string(&self) -> String {
        match self {
            Address::Domain(dom) => dom.as_ref().clone(),
            Address::Ipv4(ipv4) => ipv4.to_string(),
            Address::Ipv6(ipv6) => ipv6.to_string(),
        }
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => Address::Ipv4(ipv4),
            IpAddr::V6(ipv6) => Address::Ipv6(ipv6),
        }
    }
}

/// Convert into SocketAddr (with a port)
/// This does a DNS lookup for the Address::Domain variant.
async fn address_port_into_socket_addr<A: Borrow<Address>>(
    addr: A,
    port: u16,
) -> Result<SocketAddr, tokio::io::Error> {
    let addr = addr.borrow();
    match addr {
        Address::Ipv4(ipv4) => Ok(SocketAddr::V4(SocketAddrV4::new(*ipv4, port))),
        Address::Ipv6(ipv6) => Ok(SocketAddr::V6(SocketAddrV6::new(*ipv6, port, 0, 0))),
        Address::Domain(dom_name) => {
            let sockaddrs: Vec<_> = tokio::net::lookup_host((dom_name.as_str(), port))
                .await?
                .collect();
            if sockaddrs.len() == 0 {
                // Make new error type
                panic!("DNS resolution for {:?} failed", dom_name);
            } else {
                Ok(sockaddrs[0])
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

/// Commands sent by the client to the server
///
/// address and port have different semantics, depending on the command.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub address: Address,
    pub port: u16,
}

impl Request {
    pub async fn as_socketaddr(&self) -> Result<SocketAddr, tokio::io::Error> {
        Ok(address_port_into_socket_addr(&self.address, self.port).await?)
    }

    pub fn connect(address: Address, port: u16) -> Self {
        let command = Command::Connect;
        Self {
            command,
            address,
            port,
        }
    }

    pub fn bind(address: Address, port: u16) -> Self {
        let command = Command::Bind;
        Self {
            command,
            address,
            port,
        }
    }
    pub fn udp_associate(address: Address, port: u16) -> Self {
        let command = Command::UdpAssociate;
        Self {
            command,
            address,
            port,
        }
    }
}

impl Packet for Request {
    fn parse(input: &[u8]) -> parse::IResult<&[u8], Self> {
        parse::request(input)
    }

    fn pack_len(&self) -> usize {
        // three 1-byte fields + the 2-bytes port
        5 + self.address.pack_len()
    }

    fn pack<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], PackError> {
        if buf.len() < self.pack_len() {
            return Err(PackError::BufferTooShort {
                need: self.pack_len(),
                got: buf.len(),
            });
        }

        buf[0] = VERSION;
        buf[1] = self.command.to_u8().unwrap();
        buf[2] = 0x00; // reserved
        let addr_out = self.address.pack(&mut buf[3..]).unwrap();
        let port_offset = 3 + addr_out.len();
        buf[port_offset..port_offset + 2].clone_from_slice(self.port.to_be_bytes().as_slice());

        Ok(&buf[..self.pack_len()])
    }
}

#[derive(Debug, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum ReplyCode {
    Success = 0x00,
    ServerFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSUpported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// Replies sent by the server to th client
///
/// Address and port have different semantics depending on the associated Command.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: ReplyCode,
    pub address: Address,
    pub port: u16,
}

impl Packet for Reply {
    fn parse(input: &[u8]) -> parse::IResult<&[u8], Self> {
        parse::reply(input)
    }

    fn pack_len(&self) -> usize {
        // three 1-byte fields + 2-bytes port + address
        5 + self.address.pack_len()
    }

    fn pack<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], PackError> {
        if buf.len() < self.pack_len() {
            return Err(PackError::BufferTooShort {
                need: self.pack_len(),
                got: buf.len(),
            });
        }

        buf[0] = VERSION;
        buf[1] = self.code.to_u8().unwrap();
        buf[2] = 0x00; // reserved
        let addr_out = self.address.pack(&mut buf[3..]).unwrap();
        let port_offset = 3 + addr_out.len();
        buf[port_offset..port_offset + 2].clone_from_slice(self.port.to_be_bytes().as_slice());

        Ok(&buf[..self.pack_len()])
    }
}

impl Reply {
    pub async fn as_socketaddr(&self) -> Result<SocketAddr, tokio::io::Error> {
        Ok(address_port_into_socket_addr(&self.address, self.port).await?)
    }

    pub fn is_success(&self) -> bool {
        self.code == ReplyCode::Success
    }
}

impl From<ReplyCode> for Reply {
    fn from(code: ReplyCode) -> Self {
        Self {
            code,
            address: Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn parse_version() {
        // Correct version
        assert!(parse::version(&vec![VERSION]).is_ok());

        // Wrong version
        assert_eq!(
            parse::version(&vec![0x00]),
            Err(nom::Err::Error(parse::Error::Version(0x00)))
        );
        assert_eq!(
            parse::version(&vec![0xff, 0x12]),
            Err(nom::Err::Error(parse::Error::Version(0xff)))
        );

        // Empty: still an error but not the Version one
        let data = vec![];
        let r = parse::version(&data);
        assert!(r.is_err());
        if let nom::Err::Error(parse::Error::Version(_)) = r.unwrap_err() {
            assert!(false);
        }
    }

    #[test]
    fn parse_auth_method_proposal() {
        fn test_hex_packet(hex_packet: &str, expected_methods: Vec<AuthMethod>) {
            assert_eq!(
                AuthMethodProposal::parse(hex::decode(hex_packet).unwrap().as_slice()).unwrap(),
                (b"".as_slice(), AuthMethodProposal(expected_methods))
            );
        }

        test_hex_packet("050100", vec![AuthMethod::NO_AUTH]);
        test_hex_packet(
            "0503020100",
            vec![
                AuthMethod::USER_PASS,
                AuthMethod::GSS_API,
                AuthMethod::NO_AUTH,
            ],
        );

        // empty methods
        {
            let data = hex::decode("05001234").unwrap();
            let r = AuthMethodProposal::parse(&data);
            assert_eq!(r, Err(nom::Err::Error(parse::Error::EmptyMethodList)));
        }

        // duplicate methods
        {
            let data = hex::decode("0503112311").unwrap();
            let r = AuthMethodProposal::parse(&data);
            assert_eq!(r, Err(nom::Err::Error(parse::Error::DuplicateMethod(0x11))));
        }

        // invalid method 0xff
        {
            let data = hex::decode("05031123ff").unwrap();
            let r = AuthMethodProposal::parse(&data);
            assert_eq!(r, Err(nom::Err::Error(parse::Error::NoMethod)));
        }
    }

    #[test]
    fn parse_request_packet() {
        // Standard Connect
        {
            let data = hex::decode("050100030e7777772e676f6f676c652e636f6d01bb").unwrap();
            let r = Request::parse(&data);
            assert_eq!(
                r.unwrap(),
                (
                    b"".as_slice(),
                    Request {
                        command: Command::Connect,
                        address: Address::Domain("www.google.com".parse().unwrap()),
                        port: 443
                    }
                )
            );
        }

        // UDP Associate with zeros
        {
            let data = hex::decode("05030001000000000000").unwrap();
            let r = Request::parse(&data);
            assert_eq!(
                r.unwrap(),
                (
                    b"".as_slice(),
                    Request {
                        command: Command::UdpAssociate,
                        address: Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
                        port: 0
                    }
                )
            );
        }

        // Bind ipv6
        {
            let data = hex::decode("0502000420010db800000000000000000000cafe04d2").unwrap();
            let r = Request::parse(&data);
            assert_eq!(
                r.unwrap(),
                (
                    b"".as_slice(),
                    Request {
                        command: Command::Bind,
                        address: Address::Ipv6(Ipv6Addr::from_str("2001:db8::cafe").unwrap()),
                        port: 1234
                    }
                )
            );
        }
    }

    #[test]
    fn parse_reply_packet() {
        {
            let data = hex::decode("05000001000000000000").unwrap();
            let r = Reply::parse(&data);
            assert_eq!(
                r.unwrap(),
                (
                    &b""[..],
                    Reply {
                        code: ReplyCode::Success,
                        address: Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
                        port: 0
                    }
                )
            );
        }

        {
            let data = hex::decode("050100010000000000ff").unwrap();
            let r = Reply::parse(&data);
            assert_eq!(
                r.unwrap(),
                (
                    &b""[..],
                    Reply {
                        code: ReplyCode::ServerFailure,
                        address: Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
                        port: 255
                    }
                )
            );
        }
    }

    #[test]
    fn pack_request_connect_domain() {
        let pkt = Request {
            command: Command::Connect,
            address: Address::Domain("www.google.com".parse().unwrap()),
            port: 443,
        };
        let mut buf = vec![0; 255];
        assert_eq!(pkt.pack_len(), 4 + 1 + 14 + 2);
        let out = pkt.pack(&mut buf).unwrap();
        assert_eq!(out.len(), pkt.pack_len());
        assert_eq!(
            out,
            hex::decode("050100030e7777772e676f6f676c652e636f6d01bb").unwrap()
        );
    }

    #[test]
    fn pack_request_udpassoc_zeros() {
        let pkt = Request {
            command: Command::UdpAssociate,
            address: Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
        };
        let mut buf = vec![0; 255];
        assert_eq!(pkt.pack_len(), 4 + 4 + 2);
        let out = pkt.pack(&mut buf).unwrap();
        assert_eq!(out.len(), pkt.pack_len());
        assert_eq!(out, hex::decode("05030001000000000000").unwrap());
    }

    #[test]
    fn pack_request_bind_ipv6() {
        let pkt = Request {
            command: Command::Bind,
            address: Address::Ipv6(Ipv6Addr::from_str("2001:db8::cafe").unwrap()),
            port: 1234,
        };
        let mut buf = vec![0; 255];
        assert_eq!(pkt.pack_len(), 4 + 16 + 2);
        let out = pkt.pack(&mut buf).unwrap();
        assert_eq!(out.len(), pkt.pack_len());
        assert_eq!(
            out,
            hex::decode("0502000420010db800000000000000000000cafe04d2").unwrap()
        );
    }
}
