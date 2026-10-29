//! Query options: dig's `+` options, one set for query files and the command line (D32, D34).

use std::num::NonZeroU8;
use std::str::FromStr;
use std::time::Duration;

use dedens_net::exchange::{self, Transport};
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::text::decode_hex;
use dedens_proto::{Edns, EdnsFlags, Flags, Message, Question};
use serde::Deserialize;

/// How to ask a query, each option by its name in dig. Each field left out takes its value from the level above
/// (the command line over the query, the query over its file), then dig's default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// TCP from the start. Default: UDP, then TCP on a truncated response (RFC 7766 §5).
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub tcp: Option<bool>,
    /// DNS over TLS (RFC 7858), its server on port 853 unless given another; over `tcp`. Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub tls: Option<bool>,
    /// Keep a truncated UDP response instead of asking again over TCP. Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub ignore: Option<bool>,
    /// Recursion desired, RD (RFC 1035 §4.1.1). Default: on.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub recurse: Option<bool>,
    /// Checking disabled, CD (RFC 4035 §3.2.2). Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub cdflag: Option<bool>,
    /// Authentic data wanted, AD (RFC 6840 §5.7). Default: on, as dig.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub adflag: Option<bool>,
    /// EDNS (RFC 6891). Default: on.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub edns: Option<bool>,
    /// The UDP payload size advertised with EDNS. Default: 1232 (D10).
    #[cfg_attr(feature = "clap", arg(long, value_name = "BYTES"))]
    pub bufsize: Option<u16>,
    /// DNSSEC records wanted, DO, with EDNS (RFC 3225 §3). Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub dnssec: Option<bool>,
    /// The server's identifier asked, with EDNS (RFC 5001). Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub nsid: Option<bool>,
    /// The cookie, with EDNS (RFC 7873): true, false, or 16 hex digits of a client cookie, then optionally a
    /// server cookie. Default: on.
    #[cfg_attr(
        feature = "clap",
        arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", value_name = "COOKIE")
    )]
    #[serde(default, deserialize_with = "crate::parsed_some")]
    pub cookie: Option<CookieOption>,
    /// How long to wait for each response: seconds, or `500ms`. Default: 5 s.
    #[cfg_attr(feature = "clap", arg(long, value_name = "TIME"))]
    #[serde(default, deserialize_with = "crate::parsed_some")]
    pub time: Option<Timeout>,
    /// Queries sent before giving up when no response comes. Default: 3.
    #[cfg_attr(feature = "clap", arg(long, value_name = "N"))]
    pub tries: Option<NonZeroU8>,
}

impl Options {
    /// Each field of `self`, else of `fallback`.
    #[must_use]
    pub fn or(self, fallback: Self) -> Self {
        Self {
            tcp: self.tcp.or(fallback.tcp),
            tls: self.tls.or(fallback.tls),
            ignore: self.ignore.or(fallback.ignore),
            recurse: self.recurse.or(fallback.recurse),
            cdflag: self.cdflag.or(fallback.cdflag),
            adflag: self.adflag.or(fallback.adflag),
            edns: self.edns.or(fallback.edns),
            bufsize: self.bufsize.or(fallback.bufsize),
            dnssec: self.dnssec.or(fallback.dnssec),
            nsid: self.nsid.or(fallback.nsid),
            cookie: self.cookie.or(fallback.cookie),
            time: self.time.or(fallback.time),
            tries: self.tries.or(fallback.tries),
        }
    }

    /// Whether the options agree: EDNS is not turned off when an option that needs it is on.
    ///
    /// # Errors
    ///
    /// [`InvalidOption`] for `edns: false` with `bufsize`, `dnssec`, `nsid` or a cookie.
    pub fn check(&self) -> Result<(), InvalidOption> {
        let needs_edns = self.bufsize.is_some()
            || self.dnssec == Some(true)
            || self.nsid == Some(true)
            || matches!(self.cookie, Some(CookieOption::On | CookieOption::Fixed(_)));
        if self.edns == Some(false) && needs_edns {
            return Err(InvalidOption(
                "bufsize, dnssec, nsid and cookie need EDNS, which noedns turns off",
            ));
        }
        Ok(())
    }

    /// The query for `question`, with ID 0: [`Client::exchange`](dedens_net::client::Client::exchange) picks one.
    #[must_use]
    pub fn query<'a>(&self, question: Question<'a>) -> Message<'a> {
        let mut query = Message::query(0, question);
        let mut flags = Flags::NONE;
        for (flag, option, default) in [
            (Flags::RD, self.recurse, true),
            (Flags::AD, self.adflag, true),
            (Flags::CD, self.cdflag, false),
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
        if self.tls == Some(true) {
            options.transport = Transport::Tls;
        } else if self.tcp == Some(true) {
            options.transport = Transport::Tcp;
        }
        options.tcp_fallback = self.ignore != Some(true);
        options.cookies = self.cookie != Some(CookieOption::Off);
        if let Some(Timeout(timeout)) = self.time {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        let mut bytes = Vec::new();
        decode_hex(text.as_bytes(), &mut bytes).ok_or(invalid)?;
        let (client, server) = bytes.split_first_chunk().ok_or(invalid)?;
        let cookie =
            Cookie::new(*client, (!server.is_empty()).then_some(server)).map_err(|_| invalid)?;
        Ok(Self::Fixed(cookie))
    }
}

/// How long to wait for a response: `5s`, `500ms`, or a number of seconds; zero is 1 s, as in dig.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeout(pub Duration);

impl FromStr for Timeout {
    type Err = InvalidOption;

    fn from_str(text: &str) -> Result<Self, InvalidOption> {
        let (number, unit): (_, fn(u64) -> Duration) = match text.strip_suffix("ms") {
            Some(millis) => (millis, Duration::from_millis),
            None => (text.strip_suffix('s').unwrap_or(text), Duration::from_secs),
        };
        let invalid = InvalidOption("a timeout is a number of seconds, or ends in s or ms");
        if !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid);
        }
        let duration = unit(number.parse().map_err(|_| invalid)?);
        Ok(Self(if duration.is_zero() {
            Duration::from_secs(1)
        } else {
            duration
        }))
    }
}

/// An option value that does not read, or options that do not agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidOption(&'static str);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_read_with_or_without_a_unit() {
        for (text, duration) in [
            ("5", Duration::from_secs(5)),
            ("2s", Duration::from_secs(2)),
            ("250ms", Duration::from_millis(250)),
            ("0", Duration::from_secs(1)),
            ("0ms", Duration::from_secs(1)),
        ] {
            assert_eq!(text.parse(), Ok(Timeout(duration)), "{text}");
        }
        for text in ["", "s", "1.5s", "-1", "+5", "5m"] {
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
            "+1+2+3+4+5+6+7+8",
        ] {
            assert!(text.parse::<CookieOption>().is_err(), "{text}");
        }
    }

    #[test]
    fn options_needing_edns_refuse_noedns() {
        let noedns = Options {
            edns: Some(false),
            ..Options::default()
        };
        assert_eq!(noedns.check(), Ok(()));
        for needing in [
            Options {
                nsid: Some(true),
                ..noedns
            },
            Options {
                dnssec: Some(true),
                ..noedns
            },
            Options {
                bufsize: Some(512),
                ..noedns
            },
            Options {
                cookie: Some(CookieOption::On),
                ..noedns
            },
        ] {
            assert!(needing.check().is_err(), "{needing:?}");
        }
        assert_eq!(
            Options {
                cookie: Some(CookieOption::Off),
                ..noedns
            }
            .check(),
            Ok(())
        );
    }
}
