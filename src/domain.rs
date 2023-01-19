use std::str::FromStr;

use thiserror::Error;

/// A String that is a valid domain name
///
/// A valid domain name can only contain `.`-separated components.
/// Each component can only contain `[a-zA-Z0-9-]`, except for the first and last characted of each component, which cannot be `-`.
/// Each component must have a length between 1 and 63 charachters, excpet the last one, which can be empty.
///
/// The root domain is represented with `"."`, not with `""`.
/// Names are always assumed to absolute (even when they don't end in a `.`).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DomainName(String);

impl DomainName {
    /// The length of the domain name as a `.`-separated string.
    pub fn dot_len(&self) -> usize {
        self.0.len()
    }

    /// Length of the domain name following the RFC1034 encoding convention.
    ///
    /// The domain name is represented as a sequence of length-value pairs.
    /// The length is 1 byte and the value is the domain component.
    /// There is always a final zero-length component.
    #[allow(dead_code)]
    pub fn rfc1034_len(&self) -> usize {
        rfc1034_len(self.0.as_str())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for DomainName {
    type Error = DomainNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        check_valid_domain_name(&value)?;
        Ok(Self(value))
    }
}

impl TryFrom<Vec<u8>> for DomainName {
    type Error = DomainNameError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(value)?;
        s.try_into()
    }
}

impl FromStr for DomainName {
    type Err = DomainNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl Into<String> for DomainName {
    fn into(self) -> String {
        self.0
    }
}

impl AsRef<String> for DomainName {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

fn is_valid_domain_comp_char(c: char, include_dash: bool) -> bool {
    match c {
        'a'..='z' => true,
        'A'..='Z' => true,
        '0'..='9' => true,
        '-' => include_dash,
        _ => false,
    }
}

fn check_valid_domain_name_component(s: &str, last: bool) -> Result<(), DomainNameError> {
    let n = s.len();
    if n == 0 && last {
        return Ok(());
    }
    if n < 1 {
        return Err(DomainNameError::TooShort(n));
    }
    if n > 63 {
        return Err(DomainNameError::TooLong(n));
    }
    for (i, c) in s.chars().enumerate() {
        if i == 0 || i == n - 1 {
            if !is_valid_domain_comp_char(c, false) {
                return Err(DomainNameError::StartEndChar(c));
            }
        } else {
            if !is_valid_domain_comp_char(c, true) {
                return Err(DomainNameError::Char(c));
            }
        }
    }
    Ok(())
}

fn check_valid_domain_name(s: &str) -> Result<(), DomainNameError> {
    // "." is split in two empty components. Handle manually.
    if s == "." {
        return Ok(());
    }
    // "" is different: not a final empty component.
    if s == "" {
        return Err(DomainNameError::Empty);
    }

    let mut components = s.split('.').rev();
    let last = components.next().unwrap(); // Already handled the empty case.
    check_valid_domain_name_component(last, true)?;

    for comp in components {
        check_valid_domain_name_component(comp, false)?;
    }

    let tot_length = rfc1034_len(s);
    if tot_length > 255 {
        return Err(DomainNameError::TotalLength(tot_length));
    }

    Ok(())
}

/// This assumes that the input satisfies all conditions to be a valid domain name, except for the total length.
fn rfc1034_len(s: &str) -> usize {
    if s == "." {
        1
    } else {
        let mut len = s.split('.').map(|label| 1 + label.len()).sum();
        if !s.ends_with('.') {
            len += 1;
        }
        len
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum DomainNameError {
    #[error("illegal character {0:?}")]
    Char(char),
    #[error("illegal character at start or end {0:?}")]
    StartEndChar(char),
    #[error("component is too short {0} (min 2)")]
    TooShort(usize),
    #[error("component is too long {0} (max 63)")]
    TooLong(usize),
    #[error("the total length is too big {0} (max 255)")]
    TotalLength(usize),
    #[error("domain name is empty")]
    Empty,
    #[error("domain name is not valid UTF8: ")]
    NotUtf8(#[from] std::string::FromUtf8Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This is the only case where the argument `last` makes a difference
    #[test]
    fn empty_domain_component() {
        assert!(check_valid_domain_name_component("", true).is_ok());
        assert!(check_valid_domain_name_component("", false).is_err());
    }

    #[test]
    fn single_domain_components() {
        fn should_be_ok(case: &str) {
            assert!(check_valid_domain_name_component(case, true).is_ok());
            assert!(check_valid_domain_name_component(case, false).is_ok());
        }

        fn should_be_err(case: &str) {
            assert!(check_valid_domain_name_component(case, true).is_err());
            assert!(check_valid_domain_name_component(case, false).is_err());
        }

        should_be_ok("www");
        should_be_ok("ab");
        should_be_ok("ab123cde-foobar123-fgh");
        should_be_ok("11");
        should_be_ok("1-1");
        should_be_ok("x");

        should_be_err("-abc");
        should_be_err("abc-");
        should_be_err("abc cde");
        should_be_err("abc.cde");
        should_be_err("abc&cde");
        should_be_err(&String::from_iter(['x'; 64].iter()));
    }

    #[test]
    fn full_domains() {
        // simple example
        assert!(check_valid_domain_name("www.example.com").is_ok());
        // starts with a number
        assert!(check_valid_domain_name("123.56example.42com").is_ok());
        // dash in the middle
        assert!(check_valid_domain_name("ab-cd.exa-mple.c-om").is_ok());
        // starts with a dash
        assert!(check_valid_domain_name("-abc.example.com").is_err());
        // ends with a dash
        assert!(check_valid_domain_name("abc.example.com-").is_err());
        // dash at start of inner component
        assert!(check_valid_domain_name("abc.-example.com").is_err());
        // starts with a dot
        assert!(check_valid_domain_name(".example.com").is_err());
        // ends with a dot
        assert!(check_valid_domain_name("example.com.").is_ok());
        // consecutive dots
        assert!(check_valid_domain_name("example..com").is_err());
        // only two dots
        assert!(check_valid_domain_name("..").is_err());
        // single dot (the root)
        assert!(check_valid_domain_name(".").is_ok());
        // empty (this is not the root)
        assert!(check_valid_domain_name("").is_err());
        // max legal length
        assert!(check_valid_domain_name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com").is_ok());
        // max legal length with final `.`
        assert!(check_valid_domain_name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.").is_ok());
        // over the max length
        assert!(check_valid_domain_name("xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com").is_err());
    }

    #[test]
    fn domain_length() {
        let make_dom = |s: &str| -> DomainName { s.parse().unwrap() };

        assert_eq!(make_dom("com").dot_len(), 3);
        assert_eq!(make_dom(".").dot_len(), 1);
        assert_eq!(make_dom("www.example.com").dot_len(), 15);
        assert_eq!(make_dom("www.example.com.").dot_len(), 16);

        assert_eq!(make_dom("com").rfc1034_len(), 5);
        assert_eq!(make_dom(".").rfc1034_len(), 1);
        assert_eq!(make_dom("www.example.com").rfc1034_len(), 17);
        assert_eq!(make_dom("www.example.com.").rfc1034_len(), 17);
    }
}
