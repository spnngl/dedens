//! `dedensd` as an Oblivious `DoH` target (RFC 9230 §8, D79): the key, the configurations served for it, and the
//! opening of queries and sealing of replies; and the proxy role (D94), [`proxy`].

use std::fs::File;
use std::io::{self, Read as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use dedens_net::odoh::{self, Entropy};
use dedens_odoh::{
    ExchangeError, ObliviousDoHConfigs, ObliviousDoHMessage, ResponseContext, TargetKey,
    decrypt_query, encrypt_response, response_padding,
};
use dedens_server::{Budget, Budgets, DEFAULT_SHARE, Slot};
use http::{Response, StatusCode};
use zeroize::Zeroizing;

use self::proxy::{Proxy, Settings as ProxySettings};
use crate::config::guard_key;

pub(crate) mod proxy;

/// The requests a budget refused, by `budget` (D117).
const LIMITED: &str = "dedensd_odoh_limited_total";

/// How long clients may keep the configurations, in seconds (D79).
const CONFIGS_MAX_AGE: u32 = 3600;

/// The bytes of the secret a key derives from (D78).
const SECRET_LEN: usize = 32;

/// What bounds the decapsulations of a target, the HPKE opening of an unauthenticated request, 34.6 µs of a core
/// (`docs/benchmarks.md`), checked before any of it is done (D117).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// What a client network, as `dedensd` sees it (a proxy's, D91), may open: a unit is one decapsulation.
    pub(crate) client: Budget,
    /// What all clients may open together: a table of one bucket.
    pub(crate) global: Budget,
}

impl Default for Limits {
    /// A network opens 1000 a second, 3.5% of a core, with 2000 at once, as a network may validate (D117); all
    /// together 10 000 a second, a third of a core, with 20 000 at once.
    fn default() -> Self {
        Self {
            client: DEFAULT_SHARE,
            global: Budget {
                per_second: 10_000,
                burst: 20_000,
                table: 1,
            },
        }
    }
}

/// The settings of a target: where its secret comes from, the proxy role if it has it, and its limits. A reload builds
/// them again and compares: the secret is read at start only (D79), and so are the proxy's targets (D94).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    /// The file the secret is read from; `None` for one generated at start.
    key: Option<PathBuf>,
    /// The proxy role: what it forwards to; `None` for a target only.
    proxy: Option<ProxySettings>,
    limits: Limits,
}

impl Section {
    pub(crate) fn new(key: Option<&Path>, proxy: Option<ProxySettings>, limits: Limits) -> Self {
        Self {
            key: key.map(Path::to_path_buf),
            proxy,
            limits,
        }
    }

    /// The target of the settings: reads the key.
    ///
    /// # Errors
    ///
    /// As [`Target::new`].
    pub(crate) fn target(&self) -> anyhow::Result<Target> {
        let target = Target::new(self.key.as_deref(), self.limits)?;
        Ok(match &self.proxy {
            Some(settings) => target.proxying(settings.clone()),
            None => target,
        })
    }
}

/// The key of a target and the configurations that go with it, and the proxy that shares its listeners (D94).
#[derive(Debug)]
pub(crate) struct Target {
    key: TargetKey,
    /// The encoded configurations (RFC 9230 §5), served at the well-known path.
    configs: Vec<u8>,
    /// What each client network may open (D117).
    clients: Budgets,
    /// What all clients may open.
    global: Budgets,
    /// Forwards the requests that name a target of their own; `None` when `dedensd` is no proxy.
    pub(crate) proxy: Option<Proxy>,
}

impl Target {
    /// The target of the secret in `file`: 64 hexadecimal digits, as `openssl rand -hex 32` writes them; a new
    /// random one when there is no file.
    ///
    /// # Errors
    ///
    /// A file that does not read or is not 64 hexadecimal digits, or no randomness; a budget the table refuses: a
    /// burst above 2^30.
    pub(crate) fn new(file: Option<&Path>, limits: Limits) -> anyhow::Result<Self> {
        let secret = if let Some(file) = file {
            read_secret(file)?
        } else {
            let mut secret = Zeroizing::new([0; SECRET_LEN]);
            getrandom::fill(&mut *secret).context("`odoh`: no randomness for a key")?;
            secret
        };
        metrics::describe_counter!(
            LIMITED,
            "ODoH requests answered 503 before being opened: the client network or all clients were over their budget."
        );
        let key = TargetKey::derive(&secret);
        let configs = ObliviousDoHConfigs::new(vec![key.config().clone()])
            .encode()
            .context("`odoh`: the configurations do not encode")?;
        Ok(Self {
            key,
            configs,
            clients: Budgets::new(limits.client).context("`odoh`: `client_budget`")?,
            global: Budgets::new(limits.global).context("`odoh`: `budget`")?,
            proxy: None,
        })
    }

    /// The target, forwarding too as `settings` say.
    fn proxying(self, settings: ProxySettings) -> Self {
        Self {
            proxy: Some(Proxy::new(settings)),
            ..self
        }
    }

    /// The response to a GET of the configurations.
    pub(crate) fn configs(&self) -> Response<Vec<u8>> {
        odoh::configs_response(self.configs.clone(), CONFIGS_MAX_AGE)
    }

    /// The DNS query in the body of a POST from the client at `from` at second `now`, and what it takes to seal its
    /// reply (RFC 9230 §8). The network of `from` pays a unit of its budget first, then all clients of theirs,
    /// whatever the body: a body that does not parse costs less than the unit, one that decrypts costs it, and neither
    /// is done for a client over a budget (D117). `exempt` is a source on the rate limit's exempt list (D113): it pays
    /// no network unit.
    ///
    /// # Errors
    ///
    /// 503 for a client over a budget, the body neither parsed nor opened; 401 for a key identifier that is not this
    /// target's, so the client fetches the configurations again (§4.3); 400 for anything else that does not decrypt.
    pub(crate) fn open(
        &self,
        from: IpAddr,
        now: u32,
        exempt: bool,
        body: &[u8],
    ) -> Result<(Vec<u8>, ResponseContext), StatusCode> {
        // The peer of a QUIC connection completed its handshake: its address is no spoof.
        let network = (!exempt).then(|| Slot::new(from, true));
        if let Some(network) = network
            && !self.clients.admit(network, now)
        {
            return Err(limited("client", from));
        }
        if !self.global.admit(Slot::ONLY, now) {
            if let Some(network) = network {
                self.clients.refund(network);
            }
            return Err(limited("global", from));
        }
        let message = ObliviousDoHMessage::parse(body).map_err(|_| StatusCode::BAD_REQUEST)?;
        match decrypt_query(&self.key, &message) {
            Ok((plaintext, context)) => Ok((plaintext.into_dns_message(), context)),
            Err(ExchangeError::UnknownKey) => Err(StatusCode::UNAUTHORIZED),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }
}

/// The 503 of a request over the `budget` (`client` or `global`) of a target, counted and logged (D117).
fn limited(budget: &'static str, from: IpAddr) -> StatusCode {
    metrics::counter!(LIMITED, "budget" => budget).increment(1);
    tracing::debug!(%from, budget, "ODoH budget spent: 503");
    StatusCode::SERVICE_UNAVAILABLE
}

/// The response carrying `wire`, sealed and padded (RFC 9230 §6.2, §4.3); 500 when it cannot be sealed.
pub(crate) fn seal(context: ResponseContext, wire: &[u8]) -> Result<Response<Vec<u8>>, StatusCode> {
    let mut entropy = Entropy::new().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = encrypt_response(context, wire, response_padding(wire.len()), &mut entropy)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    entropy
        .finish()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(odoh::target_response(&message))
}

/// The most bytes a key file holds: [`SECRET_LEN`] bytes as digits and room for whitespace.
const KEY_FILE_MAX: usize = 4 * SECRET_LEN;

/// The secret in `file`: [`SECRET_LEN`] bytes as hexadecimal digits, surrounding whitespace aside. Read into a buffer
/// of its size, wiped on drop, so that no copy of the secret is left where a growing buffer was; a file others can
/// access is refused, one its group can access warned about ([`guard_key`], D115).
fn read_secret(file: &Path) -> anyhow::Result<Zeroizing<[u8; SECRET_LEN]>> {
    let shown = file.display();
    let mut input =
        File::open(file).with_context(|| format!("`odoh`: cannot read the key {shown}"))?;
    guard_key(&input, "`odoh`", file)?;
    // One byte more than the most, to tell a file that is too long.
    let mut buffer = Zeroizing::new([0; KEY_FILE_MAX + 1]);
    let mut len = 0;
    while let Some(rest) = buffer.get_mut(len..).filter(|rest| !rest.is_empty()) {
        match input.read(rest) {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(error).with_context(|| format!("`odoh`: cannot read the key {shown}"));
            }
        }
    }
    ensure!(
        len <= KEY_FILE_MAX,
        "`odoh`: the key {shown} is longer than {KEY_FILE_MAX} bytes"
    );
    let text = buffer.get(..len).unwrap_or_default().trim_ascii();
    let (pairs, rest) = text.as_chunks::<2>();
    let mut secret = Zeroizing::new([0; SECRET_LEN]);
    ensure!(
        rest.is_empty() && pairs.len() == SECRET_LEN,
        "`odoh`: the key {shown} is not {} hexadecimal digits",
        2 * SECRET_LEN
    );
    for (byte, &[high, low]) in secret.iter_mut().zip(pairs) {
        let (Some(high), Some(low)) = (digit(high), digit(low)) else {
            bail!("`odoh`: the key {shown} has a character that is no hexadecimal digit");
        };
        *byte = high << 4 | low;
    }
    Ok(secret)
}

/// The value of the hexadecimal digit `digit`.
fn digit(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use dedens_odoh::{ObliviousDoHConfigs, encrypt_query};
    use tempfile::NamedTempFile;

    use super::*;

    const CLIENT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn secret_file(text: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("a file");
        file.write_all(text.as_bytes()).expect("written");
        file
    }

    /// The same secret makes the same configurations; a generated key differs each time.
    #[test]
    fn a_file_fixes_the_key() {
        let file = secret_file(&format!("{}\n", "ab".repeat(SECRET_LEN)));
        let one = Target::new(Some(file.path()), Limits::default()).expect("a target");
        let two = Target::new(Some(file.path()), Limits::default()).expect("a target");
        assert_eq!(one.configs, two.configs);
        let generated = Target::new(None, Limits::default()).expect("a target");
        assert_ne!(generated.configs, one.configs);
    }

    /// A reload compares the settings: the key's path, never its content, which is not read again.
    #[test]
    fn settings_differ_by_the_key_path() {
        let section =
            |path: Option<&str>| Section::new(path.map(Path::new), None, Limits::default());
        assert_eq!(section(Some("/a")), section(Some("/a")));
        assert_ne!(section(Some("/a")), section(Some("/b")));
        assert_ne!(section(Some("/a")), section(None));
        let proxy = |target: &str| {
            let settings = ProxySettings::new(&[target.to_owned()], None).expect("settings");
            Section::new(None, Some(settings), Limits::default())
        };
        assert_eq!(proxy("a.example"), proxy("A.example"));
        assert_ne!(proxy("a.example"), proxy("b.example"));
        assert_ne!(proxy("a.example"), section(None));
        // Nothing is read until the target is made.
        assert!(section(Some("/nonexistent/odoh.key")).target().is_err());
    }

    /// A key file longer than a key and its whitespace is refused, as is one others can access (D115); one its group
    /// can access is read.
    #[cfg(unix)]
    #[test]
    fn a_long_key_file_is_refused_and_an_exposed_one_too() {
        use std::os::unix::fs::PermissionsExt as _;
        let file = secret_file(&format!("{}\n", "ab".repeat(KEY_FILE_MAX)));
        let error = Target::new(Some(file.path()), Limits::default()).unwrap_err();
        assert!(format!("{error:#}").contains("longer"), "{error:#}");
        let file = secret_file(&format!("  {}\n\n\n", "ab".repeat(SECRET_LEN)));
        assert!(
            Target::new(Some(file.path()), Limits::default()).is_ok(),
            "whitespace around"
        );
        let mode = |mode| {
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode))
                .expect("set");
            Target::new(Some(file.path()), Limits::default())
        };
        assert!(mode(0o600).is_ok());
        assert!(mode(0o640).is_ok(), "warned about");
        for exposed in [0o644, 0o604, 0o602, 0o666] {
            let error = mode(exposed).unwrap_err();
            assert!(
                format!("{error:#}").contains("by others"),
                "{exposed:o}: {error:#}"
            );
        }
    }

    #[test]
    fn a_key_file_that_is_not_hex_is_refused() {
        for text in [
            "",
            "ab",
            &"zz".repeat(SECRET_LEN),
            &"ab".repeat(SECRET_LEN + 1),
        ] {
            let file = secret_file(text);
            assert!(
                Target::new(Some(file.path()), Limits::default()).is_err(),
                "{text:?}"
            );
        }
        assert!(Target::new(Some(Path::new("/nonexistent/odoh.key")), Limits::default()).is_err());
    }

    /// RFC 9230 §4.3: a query opens to the DNS message and its reply seals to the client; a query to another key is
    /// 401, garbage 400.
    #[test]
    fn queries_open_and_replies_seal() {
        let target = Target::new(None, Limits::default()).expect("a target");
        let configs = ObliviousDoHConfigs::parse(&target.configs).expect("configurations");
        let mut entropy = Entropy::new().expect("randomness");
        let (message, context) =
            encrypt_query(&configs.configs()[0], b"query", 0, &mut entropy).expect("a query");
        let (wire, sealing) = target
            .open(CLIENT, 0, false, &message.encode())
            .expect("opens");
        assert_eq!(wire, b"query");
        let response = seal(sealing, b"reply").expect("seals");
        assert_eq!(response.status(), StatusCode::OK);
        let sealed = ObliviousDoHMessage::parse(response.body()).expect("a message");
        let plaintext = dedens_odoh::decrypt_response(&context, &sealed).expect("a reply");
        assert_eq!(plaintext.dns_message(), b"reply");
        let other = Target::new(None, Limits::default()).expect("a target");
        assert_eq!(
            other.open(CLIENT, 0, false, &message.encode()).err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            target.open(CLIENT, 0, false, b"garbage").err(),
            Some(StatusCode::BAD_REQUEST)
        );
    }

    /// A target of `limits` and a source of its queries: each call is a fresh query for it.
    fn flooded(limits: Limits) -> (Target, impl FnMut() -> Vec<u8>) {
        let target = Target::new(None, limits).expect("a target");
        let configs = ObliviousDoHConfigs::parse(&target.configs).expect("configurations");
        let mut entropy = Entropy::new().expect("randomness");
        let query = move || {
            let (message, _) =
                encrypt_query(&configs.configs()[0], b"query", 0, &mut entropy).expect("a query");
            message.encode()
        };
        (target, query)
    }

    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn budget(per_second: u32, burst: u32, table: usize) -> Budget {
        Budget {
            per_second,
            burst,
            table,
        }
    }

    /// D117, audit S14: a flood of POSTs from one client network opens no more than its budget, and the 503 it gets
    /// comes before the body is parsed (garbage is 503, not 400); other networks are still opened, and the flooding
    /// one again once a second has refilled its budget.
    #[test]
    fn a_flood_from_one_network_does_not_stop_the_others() {
        let (target, mut query) = flooded(Limits {
            client: budget(1, 3, 1 << 8),
            ..Limits::default()
        });
        let (flood, neighbour, other) = (
            address("198.51.100.1"),
            address("198.51.100.99"),
            address("203.0.113.1"),
        );
        let opened = (0..50)
            .filter(|_| target.open(flood, 100, false, &query()).is_ok())
            .count();
        assert_eq!(opened, 3, "the burst");
        for from in [flood, neighbour] {
            assert_eq!(
                target.open(from, 100, false, &query()).err(),
                Some(StatusCode::SERVICE_UNAVAILABLE)
            );
            assert_eq!(
                target.open(from, 100, false, b"garbage").err(),
                Some(StatusCode::SERVICE_UNAVAILABLE),
                "not parsed"
            );
        }
        assert!(target.open(other, 100, false, &query()).is_ok());
        assert!(target.open(flood, 101, false, &query()).is_ok(), "refilled");
    }

    /// D117: all clients together open no more than the global budget, however many networks they come from; a
    /// request the global budget refuses gives back the unit of its network.
    #[test]
    fn many_networks_open_no_more_than_the_global_budget() {
        let (target, mut query) = flooded(Limits {
            client: budget(1, 1, 1 << 8),
            global: budget(1, 5, 1),
        });
        let opened = (0..50_u8)
            .filter(|network| {
                let from = IpAddr::from([198, 51, *network, 1]);
                target.open(from, 100, false, &query()).is_ok()
            })
            .count();
        assert_eq!(opened, 5, "the global burst");
        // The sixth network was refused by the global budget and kept its own unit.
        let sixth = IpAddr::from([198, 51, 5, 1]);
        assert_eq!(
            target.open(sixth, 100, false, &query()).err(),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert!(target.open(sixth, 101, false, &query()).is_ok());
    }

    /// D117: an exempt source (D113) pays no network unit, and the global budget still bounds it.
    #[test]
    fn an_exempt_source_pays_only_the_global_budget() {
        let (target, mut query) = flooded(Limits {
            client: budget(1, 1, 1 << 8),
            global: budget(1, 4, 1),
        });
        let proxy = address("198.51.100.1");
        let opened = (0..10)
            .filter(|_| target.open(proxy, 100, true, &query()).is_ok())
            .count();
        assert_eq!(opened, 4, "the global burst, not the network one");
    }
}
