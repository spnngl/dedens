//! Forward stages: the upstream servers over UDP and TCP, TLS (RFC 7858 §3.1), QUIC (RFC 9250 §4.1.1) or HTTP/3
//! (RFC 8484 §3) (D65, D84), how long they are waited for (D115), and DNSSEC validation (D77, D86).

use std::fs;
use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use compio::rustls::pki_types::ServerName;
use dedens_dnssec::{Limits, TrustAnchors, Validator};
use dedens_net::doh::DEFAULT_PATH;
use dedens_proto::Name;
use dedens_server::{Budgets, DEFAULT_SHARE, Forward, Pipeline, Stage, Validating, Via};
use serde::Deserialize;

use super::limits::BudgetFile;
use super::listen::{address, split_path};
use super::{MAX_TIMEOUT_MS, MAX_TRIES, unix_seconds};

/// An upstream server (D65, D84): an IP address, on port 53 unless `:PORT` follows (an IPv6 address then in
/// brackets); behind `tls://` or `quic://`, asked over TLS or QUIC, on port 853 unless set; behind `https://`, asked
/// over HTTP/3 at `/PATH` (`/dns-query` unless set), on port 443 unless set; and `#NAME` after it for the name its
/// certificate must hold, else its address. An `sdns://` stamp is a `DNSCrypt` server (D99, the `dnscrypt` feature).
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
pub(super) struct Server(dedens_server::Server);

/// The port of DNS over TLS (RFC 7858 §3.1) and over QUIC (RFC 9250 §4.1.1).
pub(super) const ENCRYPTED_PORT: u16 = 853;

/// The port of DNS over HTTPS (RFC 8484 §3, RFC 9110 §4.2.2).
pub(super) const HTTPS_PORT: u16 = 443;

impl TryFrom<String> for Server {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        if text.starts_with("sdns://") {
            return dnscrypt(&text).map(Self);
        }
        let (rest, scheme) = match text.split_once("://") {
            Some((scheme, rest)) => (rest, Some(scheme)),
            None => (text.as_str(), None),
        };
        let (rest, name) = match rest.split_once('#') {
            Some((rest, name)) if scheme.is_some() => (rest, Some(name)),
            _ => (rest, None),
        };
        let (rest, path) = match scheme {
            Some("https") => {
                let (rest, path) =
                    split_path(rest).map_err(|error| format!("`{text}`: {error}"))?;
                (rest, Some(path))
            }
            _ => (rest, None),
        };
        let port = match scheme {
            None => 53,
            Some("https") => HTTPS_PORT,
            Some(_) => ENCRYPTED_PORT,
        };
        let addr = address(rest, port)
            .ok_or_else(|| format!("`{text}`: `{rest}` is neither IP:PORT nor IP"))?;
        if let Some(name) = name
            && ServerName::try_from(name).is_err()
        {
            return Err(format!("`{text}`: `{name}` is not a name for TLS"));
        }
        if let Some(path) = &path {
            let probe = dedens_net::client::Server {
                addr,
                name: name
                    .and_then(|name| ServerName::try_from(name).ok().map(|name| name.to_owned())),
                doh: None,
                docpath: Vec::new(),
            };
            probe
                .template_at(path)
                .map_err(|error| format!("`{text}`: {error}"))?;
        }
        let name = name.map(Arc::from);
        let via = match scheme {
            None => Via::Plain,
            Some("tls") => Via::Tls(name),
            Some("quic") => Via::Quic(name),
            Some("https") => Via::Https {
                name,
                path: path.unwrap_or_else(|| Arc::from(DEFAULT_PATH)),
            },
            Some(scheme) => {
                return Err(format!(
                    "`{text}`: `{scheme}://` is not tls://, quic:// or https://"
                ));
            }
        };
        Ok(Self(dedens_server::Server { addr, via }))
    }
}

/// The `DNSCrypt` server `text` is the stamp of: a resolver's, not a relay's (D99, D102).
#[cfg(feature = "dnscrypt")]
fn dnscrypt(text: &str) -> Result<dedens_server::Server, String> {
    use dedens_net::stamp::Stamp;

    match text.parse::<Stamp>() {
        Ok(Stamp::DnsCrypt(stamp)) => Ok(dedens_server::Server {
            addr: stamp.address.socket_addr(),
            via: Via::Dnscrypt {
                stamp: Stamp::DnsCrypt(stamp).to_string().into(),
                relays: Arc::from([]),
            },
        }),
        Ok(Stamp::Relay(_)) => Err(format!(
            "`{text}` is the stamp of a DNSCrypt relay, which is no upstream server"
        )),
        Err(error) => Err(format!("`{text}`: {error}")),
    }
}

/// Without the `dnscrypt` feature a stamp is refused (D99).
#[cfg(not(feature = "dnscrypt"))]
fn dnscrypt(text: &str) -> Result<dedens_server::Server, String> {
    Err(format!(
        "`{text}`: an `sdns://` server needs a dedensd built with the dnscrypt feature"
    ))
}

/// An Anonymized `DNSCrypt` relay of a forward stage (D100): a relay stamp, or an address, which is the same relay.
/// Kept as the text of the stamp.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(super) struct Relay(Arc<str>);

#[cfg(feature = "dnscrypt")]
impl TryFrom<String> for Relay {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        use dedens_net::stamp::{Relay as Parsed, Stamp};

        let relay: Parsed = text.parse().map_err(|error| format!("`{text}`: {error}"))?;
        Ok(Self(Stamp::Relay(relay).to_string().into()))
    }
}

/// Without the `dnscrypt` feature a relay is refused (D99).
#[cfg(not(feature = "dnscrypt"))]
impl TryFrom<String> for Relay {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        Err(format!(
            "`{text}`: a relay needs a dedensd built with the dnscrypt feature"
        ))
    }
}

/// The forward stage `name` of `servers`, with the timeout and tries it sets, validating as `validation` says; with the
/// validator of `previous` when a forward stage of it validated the same way, so that a reload keeps the keys it
/// cached (D86). The `DNSCrypt` servers are asked through `relays` (D100).
///
/// # Errors
///
/// A stage without a server, `relays` with no `sdns://` server, a `timeout_ms` above [`MAX_TIMEOUT_MS`] or `tries`
/// above [`MAX_TRIES`].
pub(super) fn forward(
    name: &str,
    (servers, relays): (Vec<Server>, Vec<Relay>),
    timeout_ms: Option<NonZeroU32>,
    tries: Option<NonZeroU8>,
    validation: Validation,
    previous: &Pipeline,
) -> anyhow::Result<Forward> {
    let relays: Arc<[Arc<str>]> = relays.into_iter().map(|relay| relay.0).collect();
    let mut stamped = false;
    let servers = servers.into_iter().map(|Server(mut server)| {
        if let Via::Dnscrypt { relays: held, .. } = &mut server.via {
            held.clone_from(&relays);
            stamped = true;
        }
        server
    });
    let servers: Vec<_> = servers.collect();
    ensure!(
        relays.is_empty() || stamped,
        "stage `{name}`: `relays` needs an `sdns://` server to ask through them"
    );
    let mut forward =
        Forward::new(servers).with_context(|| format!("stage `{name}` has no server"))?;
    match validation.dnssec {
        Dnssec::Off => ensure!(
            validation.trust_anchors.is_none()
                && validation.insecure.is_empty()
                && validation.client_share.is_none(),
            "stage `{name}`: `trust_anchors`, `insecure` and `client_share` need `dnssec: validate`"
        ),
        Dnssec::Validate => {
            let validating = validating(validation.trust_anchors.as_deref(), validation.insecure)?;
            let kept = previous.stages().iter().find_map(|stage| match stage {
                Stage::Forward(old) => old.validation().filter(|old| old.tag() == validating.tag()),
                _ => None,
            });
            let mut validating = kept.cloned().unwrap_or(validating);
            // The shares are not part of what the keys were validated by: a reload that changes them keeps the
            // key cache and starts the shares' buckets again.
            let share = BudgetFile::over(validation.client_share, DEFAULT_SHARE);
            if validating.share() != share {
                validating = validating.sharing(
                    Budgets::new(share)
                        .with_context(|| format!("stage `{name}`: `client_share`"))?,
                );
            }
            forward = forward.validating(validating);
        }
    }
    if let Some(ms) = timeout_ms {
        ensure!(
            ms.get() <= MAX_TIMEOUT_MS,
            "stage `{name}`: `timeout_ms` is above {MAX_TIMEOUT_MS}, 30 s"
        );
        forward = forward.with_timeout(Duration::from_millis(u64::from(ms.get())));
    }
    if let Some(tries) = tries {
        ensure!(
            tries.get() <= MAX_TRIES,
            "stage `{name}`: `tries` is above {MAX_TRIES}"
        );
        forward = forward.with_tries(tries);
    }
    Ok(forward)
}

/// A name `insecure` leaves unvalidated (RFC 7646): in presentation format, the root's `.` included.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
pub(super) struct Insecure(Name<'static>);

impl TryFrom<String> for Insecure {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        text.parse()
            .map(Self)
            .map_err(|error| format!("`{text}` is not a name: {error}"))
    }
}

/// What a forward stage says of validation (D77).
pub(super) struct Validation {
    pub(super) dnssec: Dnssec,
    pub(super) trust_anchors: Option<PathBuf>,
    pub(super) insecure: Vec<Insecure>,
    pub(super) client_share: Option<BudgetFile>,
}

/// Whether a forward stage validates (D77): `off` or `validate`. The YAML reader takes an unquoted `off` for the
/// boolean `false` once the stage's fields are buffered for the `type` tag, so that is read as `off` too.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(try_from = "DnssecText")]
pub(super) enum Dnssec {
    #[default]
    Off,
    Validate,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DnssecText {
    Flag(bool),
    Name(String),
}

impl TryFrom<DnssecText> for Dnssec {
    type Error = String;

    fn try_from(text: DnssecText) -> Result<Self, String> {
        match text {
            DnssecText::Flag(false) => Ok(Self::Off),
            DnssecText::Name(name) if name == "off" => Ok(Self::Off),
            DnssecText::Name(name) if name == "validate" => Ok(Self::Validate),
            DnssecText::Flag(true) => Err("`dnssec` is `off` or `validate`, not `true`".to_owned()),
            DnssecText::Name(name) => Err(format!("`dnssec` is `off` or `validate`, not `{name}`")),
        }
    }
}

/// The validator of a forward stage: the anchors of `trust_anchors`, the root's unless set, and a negative anchor
/// for each name of `insecure` (RFC 7646), checked against the clock of the system (D77).
///
/// # Errors
///
/// A `trust_anchors` file that does not read or holds no anchor.
fn validating(trust_anchors: Option<&Path>, insecure: Vec<Insecure>) -> anyhow::Result<Validating> {
    let mut tag = String::from("validate");
    let mut anchors = match trust_anchors {
        None => TrustAnchors::root(),
        Some(path) => {
            let text = fs::read_to_string(path)
                .with_context(|| format!("`trust_anchors`: cannot read {}", path.display()))?;
            tag.push_str("\nanchors ");
            tag.push_str(&text);
            TrustAnchors::read(&text)
                .with_context(|| format!("`trust_anchors`: {}", path.display()))?
        }
    };
    for Insecure(name) in insecure {
        tag.push_str("\ninsecure ");
        tag.push_str(&name.to_string());
        anchors.add_negative(name);
    }
    Ok(Validating::new(
        Validator::new(anchors, Limits::default()),
        Arc::new(unix_seconds),
    )
    .tagged(&tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::*;

    /// D99: an `sdns://` server is a resolver's stamp, kept as the text the stamp parser writes, at the stamp's address;
    /// a relay's stamp and a text that is no stamp are refused, and so is any without the `dnscrypt` feature.
    #[test]
    fn a_stamp_is_a_dnscrypt_server_when_built_for_it() {
        const RESOLVER: &str = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
        const RELAY: &str = "sdns://gRE3NS4xMTkuMTQ0LjA6ODQ0Mw";
        let server = |text: &str| Server::try_from(text.to_owned()).map(|server| server.0);
        #[cfg(feature = "dnscrypt")]
        {
            let read = server(RESOLVER).expect("a resolver");
            assert_eq!(read.addr, "94.140.14.14:5443".parse().expect("an address"));
            assert_eq!(
                read.via,
                Via::Dnscrypt {
                    stamp: RESOLVER.into(),
                    relays: Arc::from([]),
                }
            );
            assert_eq!(read.to_string(), RESOLVER);
            let error = server(RELAY).expect_err("a relay");
            assert!(error.contains("relay"), "{error}");
            let error = server("sdns://AQMAAA").expect_err("not a stamp");
            assert!(error.contains("sdns://AQMAAA"), "{error}");
        }
        #[cfg(not(feature = "dnscrypt"))]
        {
            let error = server(RESOLVER).expect_err("not built");
            assert!(error.contains("dnscrypt feature"), "{error}");
            let _ = RELAY;
        }
    }

    /// D100: `relays` are relay stamps or addresses, kept as stamps; every `sdns://` server of the stage is asked through
    /// them and the others as before; a resolver's stamp, a text that is no relay and `relays` with no `sdns://`
    /// server are refused, and so is any without the `dnscrypt` feature.
    #[test]
    fn relays_go_with_the_stamped_servers_of_the_stage() {
        const RESOLVER: &str = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
        let text = |servers: &str, relays: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: [{servers}]\n    relays: [{relays}]\n"
            )
        };
        let both = format!("'{RESOLVER}', '192.0.2.1'");
        #[cfg(feature = "dnscrypt")]
        {
            let config = read(
                &text(
                    &both,
                    "'sdns://gRE3NS4xMTkuMTQ0LjA6ODQ0Mw', '192.0.2.9:8443'",
                ),
                env,
                &Pipeline::default(),
            )
            .unwrap();
            let [Stage::Forward(forward)] = config.pipeline.stages() else {
                panic!("a forward stage")
            };
            let held = format!("{forward:?}");
            assert_eq!(held.matches("Dnscrypt").count(), 1, "{held}");
            assert!(
                held.contains("relays: [\"sdns://gRE3NS4xMTkuMTQ0LjA6ODQ0Mw\", \"sdns://gQ"),
                "{held}"
            );
            assert!(held.contains("Plain"), "{held}");
            for (servers, relay, needle) in [
                ("'192.0.2.1'", "'192.0.2.9'", "needs an `sdns://` server"),
                (&both[..], &format!("'{RESOLVER}'")[..], "relay"),
                (&both[..], "'relay.example'", "relay.example"),
            ] {
                let message = error(&text(servers, relay));
                assert!(message.contains(needle), "{needle}: {message}");
            }
        }
        #[cfg(not(feature = "dnscrypt"))]
        {
            let message = error(&text("'192.0.2.1'", "'192.0.2.9'"));
            assert!(message.contains("dnscrypt feature"), "{message}");
            let _ = both;
        }
    }

    #[test]
    fn upstream_servers_take_port_53_by_default_853_encrypted_and_443_over_https() {
        let server =
            |text: &str| Server::try_from(text.to_owned()).map(|server| server.0.to_string());
        for (written, read) in [
            ("192.0.2.1", "192.0.2.1:53"),
            ("[2001:db8::1]:5353", "[2001:db8::1]:5353"),
            ("2001:db8::1", "[2001:db8::1]:53"),
            ("[2001:db8::1]", "[2001:db8::1]:53"),
            (
                "tls://1.1.1.1#one.one.one.one",
                "tls://1.1.1.1:853#one.one.one.one",
            ),
            ("tls://[2001:db8::1]:8853", "tls://[2001:db8::1]:8853"),
            (
                "quic://94.140.14.140#dns.adguard-dns.com",
                "quic://94.140.14.140:853#dns.adguard-dns.com",
            ),
            ("tls://192.0.2.1#192.0.2.1", "tls://192.0.2.1:853#192.0.2.1"),
            (
                "https://9.9.9.9#dns.quad9.net",
                "https://9.9.9.9:443/dns-query#dns.quad9.net",
            ),
            (
                "https://[2001:db8::1]:8443/doh/query",
                "https://[2001:db8::1]:8443/doh/query",
            ),
        ] {
            assert_eq!(server(written).as_deref(), Ok(read), "{written}");
        }
        for refused in [
            "example.com",
            "tls://dns.google",
            "https://dns.quad9.net/dns-query",
            "https://192.0.2.1/dns-query?dns=",
            "https://192.0.2.1/{?dns}",
            "https://192.0.2.1/a b",
            "192.0.2.1#dns.example",
            "https://192.0.2.1#",
            "tls://192.0.2.1#",
            "tls://192.0.2.1#not a name",
        ] {
            assert!(server(refused).is_err(), "{refused}");
        }
    }

    /// D117: a client network's share of the validation allowance is the default's unless `client_share` says; a
    /// reload that changes it keeps the key cache (D86); without `dnssec: validate` it is refused, and so are a zero,
    /// a burst the table cannot hold and a field it does not know.
    #[test]
    fn a_client_share_is_set_per_stage_and_reload_keeps_the_keys() {
        let text = |share: &str| format!("{MINIMAL}    dnssec: validate\n{share}");
        let validating = |pipeline: &Pipeline| match pipeline.stages().first() {
            Some(Stage::Forward(forward)) => forward.validation().expect("validating").clone(),
            stage => unreachable!("{stage:?}"),
        };
        let first = read(&text(""), env, &Pipeline::default()).unwrap().pipeline;
        assert_eq!(validating(&first).share(), DEFAULT_SHARE);
        let wider = read(&text("    client_share: {rate: 50}\n"), env, &first)
            .unwrap()
            .pipeline;
        let share = validating(&wider).share();
        assert_eq!(
            (share.per_second, share.burst, share.table),
            (50, DEFAULT_SHARE.burst, DEFAULT_SHARE.table)
        );
        assert!(
            validating(&first)
                .validator()
                .shares_cache(validating(&wider).validator())
        );
        for (extra, needle) in [
            ("client_share: {rate: 0}", "nonzero"),
            ("client_share: {burst: 2000000000}", "client_share"),
            ("client_share: {speed: 1}", "speed"),
        ] {
            let message = error(&text(&format!("    {extra}\n")));
            assert!(message.contains(needle), "{extra}: {message}");
        }
        let message = error(&format!("{MINIMAL}    client_share: {{rate: 1}}\n"));
        assert!(message.contains("need `dnssec: validate`"), "{message}");
    }

    /// D86: the keys a validator cached stay valid across a reload while its trust anchors and negative anchors
    /// stay; another set starts a new cache.
    #[test]
    fn a_reload_keeps_the_key_cache_while_validation_stays() {
        let text = |forward: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n    dnssec: validate\n{forward}"
            )
        };
        let validator = |pipeline: &Pipeline| match pipeline.stages().first() {
            Some(Stage::Forward(forward)) => forward
                .validation()
                .expect("a validating stage")
                .validator()
                .clone(),
            stage => unreachable!("{stage:?}"),
        };
        let first = read(&text(""), env, &Pipeline::default()).unwrap().pipeline;
        let same = read(&text(""), env, &first).unwrap().pipeline;
        assert!(
            validator(&first).shares_cache(&validator(&same)),
            "unchanged"
        );
        let insecure = read(&text("    insecure: [corp.example]\n"), env, &same)
            .unwrap()
            .pipeline;
        assert!(
            !validator(&same).shares_cache(&validator(&insecure)),
            "negative anchor added"
        );
    }

    /// A forward stage validates with `dnssec: validate`, with the root's trust anchor or the file's, and `insecure`
    /// names; by default it does not (D77).
    #[test]
    fn a_forward_stage_validates_when_asked() {
        let validates = |text: &str| match read(text, env, &Pipeline::default())
            .unwrap()
            .pipeline
            .stages()
            .first()
        {
            Some(Stage::Forward(forward)) => forward.validates(),
            stage => unreachable!("{stage:?}"),
        };
        assert!(!validates(MINIMAL));
        assert!(!validates(&format!("{MINIMAL}    dnssec: off\n")));
        assert!(!validates(&format!("{MINIMAL}    dnssec: 'off'\n")));
        assert!(validates(&format!("{MINIMAL}    dnssec: validate\n")));
        assert!(validates(&format!(
            "{MINIMAL}    dnssec: validate\n    insecure: [corp.example, internal]\n"
        )));

        let path = std::env::temp_dir().join(format!("dedensd-anchors-{}", std::process::id()));
        std::fs::write(
            &path,
            ". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
        )
        .unwrap();
        let text = format!(
            "{MINIMAL}    dnssec: validate\n    trust_anchors: {}\n",
            path.display()
        );
        assert!(validates(&text));
        std::fs::write(&path, "").unwrap();
        let message = error(&text);
        assert!(message.contains("`trust_anchors`"), "{message}");
        std::fs::remove_file(&path).unwrap();
        let message = error(&text);
        assert!(message.contains("cannot read"), "{message}");
    }

    #[test]
    fn dnssec_settings_outside_the_model_are_refused() {
        for (extra, needle) in [
            ("dnssec: sometimes", "sometimes"),
            ("dnssec: true", "not `true`"),
            (
                "dnssec: off\n    insecure: [a.example]",
                "need `dnssec: validate`",
            ),
            ("insecure: [a.example]", "need `dnssec: validate`"),
            ("trust_anchors: /nonexistent", "need `dnssec: validate`"),
            ("dnssec: validate\n    insecure: ['bad..name']", "bad..name"),
            (
                "dnssec: validate\n    trust_anchors: /nonexistent/anchors",
                "cannot read",
            ),
        ] {
            let message = error(&format!("{MINIMAL}    {extra}\n"));
            assert!(message.contains(needle), "{extra}: {message}");
        }
    }

    /// D115: a forward stage waits at most 30 s a try and tries at most 5 times a server, the limits of the system
    /// resolver (`resolv.conf`: `timeout` and `attempts`); the bounds themselves are allowed.
    #[test]
    fn forward_patience_is_bounded() {
        for (extra, message) in [
            (
                "timeout_ms: 30001",
                "stage `up`: `timeout_ms` is above 30000, 30 s",
            ),
            ("timeout_ms: 4294967295", "`timeout_ms` is above 30000"),
            ("tries: 6", "stage `up`: `tries` is above 5"),
            ("tries: 255", "`tries` is above 5"),
        ] {
            let refused = error(&format!("{MINIMAL}    {extra}\n"));
            assert!(refused.contains(message), "{extra}: {refused}");
        }
        let text = format!("{MINIMAL}    timeout_ms: 30000\n    tries: 5\n");
        assert!(read(&text, env, &Pipeline::default()).is_ok());
    }
}
