//! Query options: dig's `+` options, one set for query files and the command line (D32, D34).

use std::num::NonZeroU8;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use dedens_net::doh::Method;
use dedens_net::exchange;
use dedens_proto::edns::{Cookie, Edns, EdnsFlags, EdnsOption};
use dedens_proto::{Flags, Message, Name, Question, Transport, decode_hex};
use serde::Deserialize;

/// How to ask a query, each option by its name in dig. Each field left out takes its value from the level above
/// (the command line over the query, the query over its file), then dig's default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// TCP from the start. Default: UDP, then TCP on a truncated response (RFC 7766 §5).
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub tcp: Option<bool>,
    /// DNS over TLS (RFC 7858), its server on port 853 unless given another; over `tcp`. Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub tls: Option<bool>,
    /// DNS over QUIC (RFC 9250), its server on UDP port 853 unless given another; over `tls` and `tcp`. Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub quic: Option<bool>,
    /// DNS over HTTPS (RFC 8484) over HTTP/3, its server on UDP port 443 unless given another: true, false, or the
    /// path of its URI, which `https://HOST/PATH` as a server overrides. Default path: /dns-query. Not with `tcp`, `tls`
    /// or `quic`. Default: off.
    #[cfg_attr(
        feature = "clap",
        arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", value_name = "PATH")
    )]
    #[serde(default, deserialize_with = "crate::parsed_some")]
    pub https: Option<HttpsOption>,
    /// DNS over HTTPS with the query in the URI of a GET, as `https` does by default. Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub https_get: Option<bool>,
    /// DNS over HTTPS with the query in the body of a POST. Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub https_post: Option<bool>,
    /// Oblivious DNS over HTTPS (RFC 9230) over HTTP/3 through this proxy, an `https://HOST[:PORT][/PATH]` URI, to the
    /// server, which must be an `https://` one: the target. Built with the `odoh` feature only (D69). Not with `tcp`,
    /// `tls`, `quic` or `https_get`. Default: off.
    #[cfg_attr(feature = "clap", arg(long, value_name = "URI"))]
    pub odoh_proxy: Option<String>,
    /// DNS over CoAP (RFC 9953), unprotected, over UDP, its server on port 5683 unless given another: the `doc`
    /// feature of the build. Not with `tcp`, `tls`, `quic`, `https` or `odoh_proxy`. Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub coap: Option<bool>,
    /// Ask the CoAP server for its `DoC` resource, GET `/.well-known/core?rt=core.dns`, and query the first it lists,
    /// instead of the path of the URI (RFC 9953 §3.1; D95). The server is the one named, never found: the
    /// list is as trusted as the server is. Needs CoAP (`coap`, or a `coap://` server) with no path in the server's URI.
    /// Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub doc_discover: Option<bool>,
    /// List the certificates of a `DNSCrypt` resolver, the server, which must be an `sdns://` stamp (D98): their
    /// system, serial and validity, instead of an answer. Not with `tls`, `quic`, `https`, `odoh_proxy` or `coap`.
    /// Default: off.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub dnscrypt_cert: Option<bool>,
    /// Ask the `DNSCrypt` resolver, the server, which must be an `sdns://` stamp, through this relay (Anonymized
    /// `DNSCrypt`, D100), so that the resolver never sees the client's address: an `sdns://` relay stamp, or an
    /// address with an optional port (443). Certificates are asked through it too. Not with `tls`, `quic`, `https`,
    /// `odoh_proxy` or `coap`. Default: direct.
    #[cfg_attr(feature = "clap", arg(long, value_name = "RELAY"))]
    pub dnscrypt_relay: Option<String>,
    /// A file with the target's key configurations (RFC 9230 §5), as the target serves them, for `odoh_proxy`: they
    /// are not fetched from the target, which would give it the client's address, and no query is linked to it. Read
    /// once, before any query: a file that cannot be read or holds no configurations (RFC 9230 §6) is a usage error.
    /// Default: fetched from the target.
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE"))]
    pub odoh_config: Option<String>,
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
    /// Validate the response as a validating stub resolver (RFC 4035 §4.9): DO and CD set, the chain of trust asked
    /// of the same server, a verdict beside the response (D76). The server is the transport, not trusted: its AD flag is
    /// never read. Not with `noedns`, `nodnssec` or `nocdflag`. Default: off, unless `trust_anchor` or `insecure` is given.
    #[cfg_attr(feature = "clap", arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true"))]
    pub validate: Option<bool>,
    /// A file of DS or DNSKEY records in zone text, the trust anchors of validation instead of the root's (RFC 4035 §4.4).
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE"))]
    pub trust_anchor: Option<PathBuf>,
    /// A negative trust anchor (RFC 7646): names at or below it are insecure, not validated. The command line repeats it.
    #[cfg_attr(feature = "clap", arg(long, value_name = "NAME"))]
    #[serde(default, deserialize_with = "crate::parsed_list")]
    pub insecure: Option<Vec<Name<'static>>>,
}

impl Options {
    /// Each field of `self`, else of `fallback`.
    #[must_use]
    pub fn or(self, fallback: Self) -> Self {
        Self {
            tcp: self.tcp.or(fallback.tcp),
            tls: self.tls.or(fallback.tls),
            quic: self.quic.or(fallback.quic),
            https: self.https.or(fallback.https),
            https_get: self.https_get.or(fallback.https_get),
            https_post: self.https_post.or(fallback.https_post),
            odoh_proxy: self.odoh_proxy.or(fallback.odoh_proxy),
            coap: self.coap.or(fallback.coap),
            doc_discover: self.doc_discover.or(fallback.doc_discover),
            dnscrypt_cert: self.dnscrypt_cert.or(fallback.dnscrypt_cert),
            dnscrypt_relay: self.dnscrypt_relay.or(fallback.dnscrypt_relay),
            odoh_config: self.odoh_config.or(fallback.odoh_config),
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
            validate: self.validate.or(fallback.validate),
            trust_anchor: self.trust_anchor.or(fallback.trust_anchor),
            insecure: self.insecure.or(fallback.insecure),
        }
    }

    /// Whether the options agree: EDNS is not turned off when an option that needs it is on.
    ///
    /// # Errors
    ///
    /// [`InvalidOption`] for `edns: false` with `bufsize`, `dnssec`, `nsid`, a cookie, or TLS, QUIC or HTTPS, whose queries are padded with
    /// EDNS (RFC 8467 §4.1); HTTPS together with `tcp`, `tls` or `quic`, or `https_get` with `https_post`; `odoh_proxy` with `tcp`, `tls`,
    /// `quic` or `https_get`; CoAP with `tcp`, `tls`, `quic`, HTTPS or `odoh_proxy`; `odoh_config` without
    /// `odoh_proxy`; `dnscrypt_cert` or `dnscrypt_relay` with `tls`, `quic`, HTTPS, `odoh_proxy` or CoAP, which a
    /// `DNSCrypt` server goes with none of.
    pub fn check(&self) -> Result<(), InvalidOption> {
        let needs_edns = self.bufsize.is_some()
            || self.dnssec == Some(true)
            || self.nsid == Some(true)
            || matches!(self.cookie, Some(CookieOption::On | CookieOption::Fixed(_)))
            || self.encrypted()
            || self.https()
            || self.validating();
        if self.edns == Some(false) && needs_edns {
            return Err(InvalidOption(
                "bufsize, dnssec, nsid, cookie, tls, quic, https and validate need EDNS, which noedns turns off",
            ));
        }
        if self.validating() && (self.dnssec == Some(false) || self.cdflag == Some(false)) {
            return Err(InvalidOption(
                "validate sets DO and CD: no nodnssec or nocdflag",
            ));
        }
        if self.https() && (self.tcp == Some(true) || self.encrypted()) {
            return Err(InvalidOption(
                "https goes with no tcp, tls or quic: it is HTTP/3, over QUIC",
            ));
        }
        if self.odoh() && (self.tcp == Some(true) || self.encrypted()) {
            return Err(InvalidOption(
                "odoh-proxy goes with no tcp, tls or quic: it is HTTP/3, over QUIC",
            ));
        }
        if self.odoh() && self.https_get == Some(true) {
            return Err(InvalidOption("odoh-proxy sends by POST: no https-get"));
        }
        if self.odoh_config.is_some() && !self.odoh() {
            return Err(InvalidOption("odoh-config goes with odoh-proxy"));
        }
        if self.https_get == Some(true) && self.https_post == Some(true) {
            return Err(InvalidOption("https-get and https-post exclude each other"));
        }
        if self.coap == Some(true)
            && (self.tcp == Some(true) || self.encrypted() || self.https() || self.odoh())
        {
            return Err(InvalidOption(
                "coap goes with no tcp, tls, quic, https or odoh-proxy: it is CoAP over UDP",
            ));
        }
        if (self.dnscrypt_cert == Some(true) || self.dnscrypt_relay.is_some())
            && (self.encrypted() || self.https() || self.odoh() || self.coap == Some(true))
        {
            return Err(InvalidOption(
                "dnscrypt-cert and dnscrypt-relay go with no tls, quic, https, odoh-proxy or coap: they ask a DNSCrypt server",
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
            (Flags::CD, self.cdflag, self.validating()),
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
            if self.dnssec.unwrap_or_else(|| self.validating()) {
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

    /// Whether responses are validated: `validate` on, or unset with a trust anchor or a negative one given.
    #[must_use]
    pub fn validating(&self) -> bool {
        self.validate.unwrap_or_else(|| {
            self.trust_anchor.is_some()
                || self
                    .insecure
                    .as_ref()
                    .is_some_and(|names| !names.is_empty())
        })
    }

    /// Whether the server is asked over TLS or QUIC, whose port is 853.
    #[must_use]
    pub fn encrypted(&self) -> bool {
        self.tls == Some(true) || self.quic == Some(true)
    }

    /// Whether the server is asked over Oblivious `DoH`: `odoh_proxy` is given.
    #[must_use]
    pub const fn odoh(&self) -> bool {
        self.odoh_proxy.is_some()
    }

    /// Whether the server is asked over HTTPS: `https` on or with a path, else `https_get` or `https_post` on.
    #[must_use]
    pub fn https(&self) -> bool {
        match self.https {
            Some(HttpsOption::Off) => false,
            Some(HttpsOption::On | HttpsOption::Path(_)) => true,
            None => self.https_get == Some(true) || self.https_post == Some(true),
        }
    }

    /// The path of the URI of the HTTPS server, when `https` gives one.
    #[must_use]
    pub fn https_path(&self) -> Option<&str> {
        match &self.https {
            Some(HttpsOption::Path(path)) => Some(path),
            _ => None,
        }
    }

    /// The exchange options: transport, HTTP method, TCP fallback, cookies, timeout and tries.
    #[must_use]
    pub fn exchange(&self) -> exchange::Options {
        let mut options = exchange::Options::default();
        if self.odoh() {
            options.transport = Transport::Odoh;
        } else if self.https() {
            options.transport = Transport::Https;
            if self.https_post == Some(true) {
                options.method = Method::Post;
            }
        } else if self.coap == Some(true) {
            options.transport = Transport::Coap;
        } else if self.quic == Some(true) {
            options.transport = Transport::Quic;
        } else if self.tls == Some(true) {
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

/// The `https` option: written `true`, `false`, or the path of the server's URI, which starts with `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpsOption {
    /// The default path.
    On,
    /// Off.
    Off,
    /// This path.
    Path(String),
}

impl FromStr for HttpsOption {
    type Err = InvalidOption;

    fn from_str(text: &str) -> Result<Self, InvalidOption> {
        match text {
            "true" => Ok(Self::On),
            "false" => Ok(Self::Off),
            path if path.starts_with('/') => Ok(Self::Path(path.to_owned())),
            _ => Err(InvalidOption(
                "https is true, false, or a path starting with /",
            )),
        }
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
                ..noedns.clone()
            },
            Options {
                dnssec: Some(true),
                ..noedns.clone()
            },
            Options {
                bufsize: Some(512),
                ..noedns.clone()
            },
            Options {
                cookie: Some(CookieOption::On),
                ..noedns.clone()
            },
            Options {
                tls: Some(true),
                ..noedns.clone()
            },
            Options {
                quic: Some(true),
                ..noedns.clone()
            },
            Options {
                https: Some(HttpsOption::On),
                ..noedns.clone()
            },
        ] {
            assert!(needing.check().is_err(), "{needing:?}");
        }
        assert_eq!(
            Options {
                cookie: Some(CookieOption::Off),
                ..noedns.clone()
            }
            .check(),
            Ok(())
        );
    }

    #[test]
    fn https_reads_as_a_switch_or_a_path() {
        assert_eq!("true".parse(), Ok(HttpsOption::On));
        assert_eq!("false".parse(), Ok(HttpsOption::Off));
        assert_eq!("/dns".parse(), Ok(HttpsOption::Path("/dns".to_owned())));
        for text in ["", "dns", "dns-query", "1"] {
            assert!(text.parse::<HttpsOption>().is_err(), "{text}");
        }
    }

    #[test]
    fn https_is_on_with_a_path_or_either_method() {
        let https = |https, get, post| Options {
            https,
            https_get: get,
            https_post: post,
            ..Options::default()
        };
        assert!(!Options::default().https());
        assert!(https(Some(HttpsOption::On), None, None).https());
        assert!(https(Some(HttpsOption::Path("/p".to_owned())), None, None).https());
        assert!(!https(Some(HttpsOption::Off), Some(true), None).https());
        assert!(https(None, Some(true), None).https());
        assert!(https(None, None, Some(true)).https());
        assert!(!https(None, None, Some(false)).https());
        let path = https(Some(HttpsOption::Path("/p".to_owned())), None, None);
        assert_eq!(path.https_path(), Some("/p"));
        assert_eq!(Options::default().https_path(), None);
    }

    #[test]
    fn https_picks_the_transport_and_the_method() {
        let get = Options {
            https_get: Some(true),
            ..Options::default()
        };
        let options = get.exchange();
        assert_eq!(options.transport, Transport::Https);
        assert_eq!(options.method, Method::Get);
        let post = Options {
            https_post: Some(true),
            ..Options::default()
        };
        let options = post.exchange();
        assert_eq!(options.transport, Transport::Https);
        assert_eq!(options.method, Method::Post);
    }

    #[test]
    fn https_refuses_what_it_does_not_go_with() {
        let on = Options {
            https: Some(HttpsOption::On),
            ..Options::default()
        };
        assert_eq!(on.check(), Ok(()));
        for refused in [
            Options {
                tcp: Some(true),
                ..on.clone()
            },
            Options {
                tls: Some(true),
                ..on.clone()
            },
            Options {
                quic: Some(true),
                ..on.clone()
            },
            Options {
                https_get: Some(true),
                https_post: Some(true),
                ..on.clone()
            },
        ] {
            assert!(refused.check().is_err(), "{refused:?}");
        }
        let off = Options {
            https: Some(HttpsOption::Off),
            tls: Some(true),
            ..Options::default()
        };
        assert_eq!(off.check(), Ok(()));
    }

    #[test]
    fn coap_picks_the_transport_and_refuses_what_it_does_not_go_with() {
        let on = Options {
            coap: Some(true),
            ..Options::default()
        };
        assert_eq!(on.check(), Ok(()));
        assert_eq!(on.exchange().transport, Transport::Coap);
        for refused in [
            Options {
                tcp: Some(true),
                ..on.clone()
            },
            Options {
                tls: Some(true),
                ..on.clone()
            },
            Options {
                quic: Some(true),
                ..on.clone()
            },
            Options {
                https: Some(HttpsOption::On),
                ..on.clone()
            },
            Options {
                odoh_proxy: Some("https://proxy.example/proxy".to_owned()),
                ..on.clone()
            },
        ] {
            assert!(refused.check().is_err(), "{refused:?}");
        }
        let off = Options {
            coap: Some(false),
            tcp: Some(true),
            ..Options::default()
        };
        assert_eq!(off.check(), Ok(()));
        assert_eq!(off.exchange().transport, Transport::Tcp);
    }

    /// D95: `doc_discover` is set in a file's `options` or on the command line, which wins; whether a server is there
    /// to ask is the caller's to check (`@coap://` is CoAP with no `coap` set).
    #[test]
    fn doc_discover_is_merged_with_the_command_line_first() {
        let line = Options {
            doc_discover: Some(false),
            ..Options::default()
        };
        let file = Options {
            doc_discover: Some(true),
            ..Options::default()
        };
        assert_eq!(line.or(file.clone()).doc_discover, Some(false));
        assert_eq!(Options::default().or(file.clone()).doc_discover, Some(true));
        assert_eq!(file.check(), Ok(()));
    }

    /// D98: `dnscrypt_cert` is merged with the command line first, and refused with the transports a `DNSCrypt` server
    /// goes with none of; whether the server is a stamp is the caller's to check.
    #[test]
    fn dnscrypt_cert_goes_with_no_other_transport() {
        let on = Options {
            dnscrypt_cert: Some(true),
            ..Options::default()
        };
        assert_eq!(on.check(), Ok(()));
        assert_eq!(
            Options {
                tcp: Some(true),
                ..on.clone()
            }
            .check(),
            Ok(())
        );
        for refused in [
            Options {
                tls: Some(true),
                ..on.clone()
            },
            Options {
                quic: Some(true),
                ..on.clone()
            },
            Options {
                https: Some(HttpsOption::On),
                ..on.clone()
            },
            Options {
                odoh_proxy: Some("https://proxy.example/proxy".to_owned()),
                ..on.clone()
            },
            Options {
                coap: Some(true),
                ..on.clone()
            },
        ] {
            assert!(refused.check().is_err(), "{refused:?}");
        }
        let line = Options {
            dnscrypt_cert: Some(false),
            ..Options::default()
        };
        assert_eq!(line.or(on.clone()).dnscrypt_cert, Some(false));
        assert_eq!(Options::default().or(on).dnscrypt_cert, Some(true));
    }

    /// D100: `dnscrypt_relay` is merged as the other options, and goes with the transports `dnscrypt_cert` goes with.
    #[test]
    fn dnscrypt_relay_goes_with_no_other_transport() {
        let relay = Options {
            dnscrypt_relay: Some("192.0.2.1".to_owned()),
            ..Options::default()
        };
        assert_eq!(relay.check(), Ok(()));
        for refused in [
            Options {
                tls: Some(true),
                ..relay.clone()
            },
            Options {
                coap: Some(true),
                ..relay.clone()
            },
        ] {
            assert!(refused.check().is_err(), "{refused:?}");
        }
        assert_eq!(
            Options::default().or(relay).dnscrypt_relay.as_deref(),
            Some("192.0.2.1")
        );
    }
}
