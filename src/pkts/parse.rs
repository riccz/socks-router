use super::*;

use nom::bytes::streaming::take;
use nom::error::ErrorKind;
use nom::error::ParseError;
use nom::multi::length_count;
use nom::number::streaming::{be_u16, u8};
use thiserror::Error;

/// Custom Error type for the parsing functions
#[derive(Debug, PartialEq, Error)]
pub enum Error {
    #[error("Nom error {0:?}")]
    Nom(ErrorKind),
    #[error("wrong SOCKS version {0} (expected {})", VERSION)]
    Version(u8),
    #[error("empty method list")]
    EmptyMethodList,
    #[error("duplicate method {0:#02x}")]
    DuplicateMethod(u8),
    #[error("too many methods {0} (max 253)")]
    TooManyMethods(u8),
    #[error("value for 'no method acceptable'")]
    NoMethod,
    #[error("domain is not valid UTF8 {0:?}")]
    NotUtf8Domain(Vec<u8>),
    #[error("unknown address tag {0:#02x}")]
    AddressTag(u8),
    #[error("unknown command tag {0:#02x}")]
    CommandTag(u8),
    #[error("unknown reply code {0:#02x}")]
    ReplyCode(u8),
    #[error("invalid domain name: {0}")]
    Domain(#[from] DomainNameError),
}

impl<I> ParseError<I> for Error {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        Error::Nom(kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

pub type IResult<I, O> = nom::IResult<I, O, Error>;

/// Parse the version field. Must be the expected one.
pub fn version(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, v) = u8(input)?;
    if v != VERSION {
        Err(nom::Err::Error(Error::Version(v)))
    } else {
        Ok((input, ()))
    }
}

pub fn auth_method(input: &[u8]) -> IResult<&[u8], Option<AuthMethod>> {
    let (input, raw) = u8(input)?;
    Ok((input, AuthMethod::new(raw)))
}

pub fn auth_method_proposal(input: &[u8]) -> IResult<&[u8], AuthMethodProposal> {
    let (input, _) = version(input)?;
    let (input, methods) = length_count(u8, auth_method)(input)?;

    if methods.is_empty() {
        return Err(nom::Err::Error(Error::EmptyMethodList));
    }
    if methods.len() > 253 {
        return Err(nom::Err::Error(Error::TooManyMethods(methods.len() as u8)));
    }

    let methods = methods
        .into_iter()
        .map(|m| m.ok_or(Error::NoMethod))
        .collect::<Result<Vec<AuthMethod>, Error>>()
        .map_err(|e| nom::Err::Error(e))?;

    // Check uniqueness
    let mut sorted_methods: Vec<u8> = methods.iter().map(|m| m.0).collect();
    sorted_methods.sort();
    for i in 0..sorted_methods.len() - 1 {
        let x = sorted_methods[i];
        let y = sorted_methods[i + 1];
        if x == y {
            return Err(nom::Err::Error(Error::DuplicateMethod(x)));
        }
    }

    Ok((input, AuthMethodProposal(methods)))
}

pub fn auth_method_response(input: &[u8]) -> IResult<&[u8], AuthMethodResponse> {
    let (input, _) = version(input)?;
    let (input, m) = auth_method(input)?;
    Ok((input, AuthMethodResponse(m)))
}

pub fn address(input: &[u8]) -> IResult<&[u8], Address> {
    let (input, addr_type) = u8(input)?;
    match addr_type {
        Address::IPV4_TAG => {
            let (input, ipv4_bytes) = take(4usize)(input)?;
            let ipv4_bytes: [u8; 4] = ipv4_bytes.try_into().unwrap();
            Ok((input, Address::Ipv4(Ipv4Addr::from(ipv4_bytes))))
        }
        Address::IPV6_TAG => {
            let (input, ipv6_bytes) = take(16usize)(input)?;
            let ipv6_bytes: [u8; 16] = ipv6_bytes.try_into().unwrap();
            Ok((input, Address::Ipv6(Ipv6Addr::from(ipv6_bytes))))
        }
        Address::DOMAIN_TAG => {
            let (input, domain_bytes) = length_count(u8, u8)(input)?;
            let domain =
                DomainName::try_from(domain_bytes).map_err(|e| nom::Err::Error(e.into()))?;
            Ok((input, Address::Domain(domain)))
        }
        x => Err(nom::Err::Error(Error::AddressTag(x))),
    }
}

pub fn request(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, _) = version(input)?;
    let (input, cmd_tag) = u8(input)?;
    let (input, _) = u8(input)?; // Skip unused byte
    let (input, address) = address(input)?;
    let (input, port) = be_u16(input)?;

    let command = Command::from_u8(cmd_tag).ok_or(nom::Err::Error(Error::CommandTag(cmd_tag)))?;
    Ok((
        input,
        Request {
            command,
            address,
            port,
        },
    ))
}

pub fn reply(input: &[u8]) -> IResult<&[u8], Reply> {
    let (input, _) = version(input)?;
    let (input, raw_reply_code) = u8(input)?;
    let (input, _) = u8(input)?; // Skip unused byte
    let (input, address) = address(input)?;
    let (input, port) = be_u16(input)?;

    let code = ReplyCode::from_u8(raw_reply_code)
        .ok_or(nom::Err::Error(Error::ReplyCode(raw_reply_code)))?;
    Ok((
        input,
        Reply {
            code,
            address,
            port,
        },
    ))
}
