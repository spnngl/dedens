//! Query options: dig's `+` options, one set for query files and the command line (D32, D34).

use std::fmt;
use std::num::NonZeroU8;
use std::str::FromStr;
use std::time::Duration;

use dedens_net::exchange::{self, Transport};
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{Edns, EdnsFlags, Flags, Message, Question};
use serde::Deserialize;

/// How to ask a query. Each field left out takes its value from the level above (the command line over the query,
/// the query over its file), then dig's default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// TCP from the start (`+tcp`). Default: UDP, then TCP on a truncated response (RFC 7766 §5).
    pub tcp: Option<bool>,
    /// A truncated UDP response is the response, not asked again over TCP (`+ignore`). Default: off.
    pub ignore: Option<bool>,
    /// RD, recursion desired (`+recurse`, RFC 1035 §4.1.1). Default: on.
    pub recurse: Option<bool>,
    /// CD, checking disabled (`+cd`, RFC 4035 §3.2.2). Default: off.
    pub cd: Option<bool>,
    /// AD, authentic data wanted (`+ad`, RFC 6840 §5.7). Default: on, as dig.
    pub ad: Option<bool>,
    /// EDNS (`+edns`, RFC 6891). Default: on.
    pub edns: Option<bool>,
    /// The UDP payload size advertised with EDNS (`+bufsize`). Default: 1232 (D10).
    pub bufsize: Option<u16>,
    /// DO, DNSSEC records wanted, with EDNS (`+dnssec`, RFC 3225 §3). Default: off.
    pub dnssec: Option<bool>,
    /// The server's identifier asked, with EDNS (`+nsid`, RFC 5001). Default: off.
    pub nsid: Option<bool>,
    /// The cookie, with EDNS (`+cookie`, RFC 7873). Default: on.
    pub cookie: Option<CookieOption>,
    /// How long to wait for each response (`+time`). Default: 5 s.
    pub timeout: Option<Timeout>,
    /// Queries sent before giving up when no response comes (`+tries`). Default: 3.
    pub tries: Option<NonZeroU8>,
}

impl Options {
    /// Each field of `self`, else of `fallback`.
    #[must_use]
    pub fn or(self, fallback: Self) -> Self {
        Self {
            tcp: self.tcp.or(fallback.tcp),
            ignore: self.ignore.or(fallback.ignore),
            recurse: self.recurse.or(fallback.recurse),
            cd: self.cd.or(fallback.cd),
            ad: self.ad.or(fallback.ad),
            edns: self.edns.or(fallback.edns),
            bufsize: self.bufsize.or(fallback.bufsize),
            dnssec: self.dnssec.or(fallback.dnssec),
            nsid: self.nsid.or(fallback.nsid),
            cookie: self.cookie.or(fallback.cookie),
            timeout: self.timeout.or(fallback.timeout),
            tries: self.tries.or(fallback.tries),
        }
    }

    /// The query for `question`, with ID 0: [`Client::exchange`](dedens_net::client::Client::exchange) picks one.
    #[must_use]
    pub fn query<'a>(&self, question: Question<'a>) -> Message<'a> {
        let mut query = Message::query(0, question);
        let mut flags = Flags::NONE;
        for (flag, option, default) in [
            (Flags::RD, self.recurse, true),
            (Flags::AD, self.ad, true),
            (Flags::CD, self.cd, false),
        ] {
            if option.unwrap_or(default) {
                flags = flags.with(flag);
            }
        }
        query.header.flags = flags;
        query.edns = self.edns.unwrap_or(true).then(|| {
            let mut edns = Edns::default();
            if let Some(size) = self.bufsize {
                edns.udp_payload = size;
            }
            if self.dnssec == Some(true) {
                edns.flags = edns.flags.with(EdnsFlags::DO);
            }
            if self.nsid == Some(true) {
                edns.options.push(EdnsOption::Nsid(Vec::new().into()));
            }
            if let Some(CookieOption::Fixed(cookie)) = self.cookie {
                edns.options.push(EdnsOption::Cookie(cookie));
            }
            edns
        });
        query
    }

    /// The exchange options: transport, TCP fallback, cookies, timeout and tries.
    #[must_use]
    pub fn exchange(&self) -> exchange::Options {
        let mut options = exchange::Options::default();
        if self.tcp == Some(true) {
            options.transport = Transport::Tcp;
        }
        options.tcp_fallback = self.ignore != Some(true);
        options.cookies = self.cookie != Some(CookieOption::Off);
        if let Some(Timeout(timeout)) = self.timeout {
            options.timeout = timeout;
        }
        if let Some(tries) = self.tries {
            options.tries = tries;
        }
        options
    }
}

/// The cookie of a query (RFC 7873 §5.1): written `true`, `false`, or the hex digits of a client cookie, 8 bytes,
/// then optionally of a server cookie, 8 to 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Scalar")]
pub enum CookieOption {
    /// A random client cookie per server, then the server cookie it returns.
    On,
    /// No cookie.
    Off,
    /// This cookie, for every query.
    Fixed(Cookie),
}

impl FromStr for CookieOption {
    type Err = InvalidOption;

    fn from_str(text: &str) -> Result<Self, InvalidOption> {
        let invalid = InvalidOption(
            "a cookie is true, false, or 16 hex digits of a client cookie, then 16 to 64 of a server cookie",
        );
        match text {
            "true" => return Ok(Self::On),
            "false" => return Ok(Self::Off),
            _ => {}
        }
        let bytes = unhex(text).ok_or(invalid)?;
        let (client, server) = bytes.split_first_chunk().ok_or(invalid)?;
        let cookie =
            Cookie::new(*client, (!server.is_empty()).then_some(server)).map_err(|_| invalid)?;
        Ok(Self::Fixed(cookie))
    }
}

/// How long to wait for a response: `5s`, `500ms`, or a number of seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Scalar")]
pub struct Timeout(pub Duration);

impl FromStr for Timeout {
    type Err = InvalidOption;

    fn from_str(text: &str) -> Result<Self, InvalidOption> {
        let (number, unit): (_, fn(u64) -> Duration) = match text.strip_suffix("ms") {
            Some(millis) => (millis, Duration::from_millis),
            None => (text.strip_suffix('s').unwrap_or(text), Duration::from_secs),
        };
        number
            .parse()
            .map(|n| Self(unit(n)))
            .map_err(|_| InvalidOption("a timeout is a number of seconds, or ends in s or ms"))
    }
}

/// An option value that does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidOption(&'static str);

/// A YAML or JSON scalar, read as text by the [`FromStr`] of an option.
#[derive(Deserialize)]
#[serde(untagged)]
enum Scalar {
    Bool(bool),
    Number(u64),
    Text(String),
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Text(text) => f.write_str(text),
        }
    }
}

impl TryFrom<Scalar> for CookieOption {
    type Error = InvalidOption;

    fn try_from(scalar: Scalar) -> Result<Self, InvalidOption> {
        scalar.to_string().parse()
    }
}

impl TryFrom<Scalar> for Timeout {
    type Error = InvalidOption;

    fn try_from(scalar: Scalar) -> Result<Self, InvalidOption> {
        scalar.to_string().parse()
    }
}

/// The bytes of an even number of hex digits.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_read_with_or_without_a_unit() {
        for (text, duration) in [
            ("5", Duration::from_secs(5)),
            ("2s", Duration::from_secs(2)),
            ("250ms", Duration::from_millis(250)),
        ] {
            assert_eq!(text.parse(), Ok(Timeout(duration)), "{text}");
        }
        for text in ["", "s", "1.5s", "-1", "5m"] {
            assert!(text.parse::<Timeout>().is_err(), "{text}");
        }
    }

    #[test]
    fn cookies_read_as_switches_or_hex() {
        assert_eq!("true".parse(), Ok(CookieOption::On));
        assert_eq!("false".parse(), Ok(CookieOption::Off));
        let client = Cookie::new(*b"\x01\x02\x03\x04\x05\x06\x07\x08", None).expect("valid");
        assert_eq!("0102030405060708".parse(), Ok(CookieOption::Fixed(client)));
        let both = "0102030405060708".to_owned() + &"ab".repeat(8);
        let CookieOption::Fixed(cookie) = both.parse().expect("valid") else {
            panic!("a fixed cookie");
        };
        assert_eq!(cookie.server(), Some([0xAB; 8].as_slice()));
        for text in [
            "",
            "01",
            "010203040506070",
            "0102030405060708ab",
            "zz02030405060708",
        ] {
            assert!(text.parse::<CookieOption>().is_err(), "{text}");
        }
    }
}
