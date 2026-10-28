//! The configuration file (D24, D44): YAML, `${VAR}` replaced first, then read into named stages run in the order
//! `pipeline` lists them.
//!
//! ```yaml
//! listen: ["127.0.0.1:53", "[::1]:53"]
//! zero_buffers: true
//! pipeline: [hosts, ads, cache, upstream]
//! stages:
//!   ads:
//!     type: blocklist
//!     file: /etc/dedensd/blocklist.hosts
//!   hosts:
//!     type: hosts
//!     entries: ["192.0.2.10 printer.lan"]
//!     file: /etc/hosts
//!   cache:
//!     type: cache
//!     capacity: 67108864
//!   upstream:
//!     type: forward
//!     servers: ["9.9.9.9", "149.112.112.112:53"]
//!     timeout_ms: 3000
//!     tries: 2
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail, ensure};
use dedens_cache::Cache;
use dedens_plugins::{Action, Blocklist, Hosts, LineError};
use dedens_proto::Ttl;
use dedens_server::{Forward, Pipeline, Stage};
use serde::Deserialize;

/// The configuration file, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// Addresses answered on, over UDP and TCP.
    listen: Vec<SocketAddr>,
    /// Whether a reused reply buffer is zeroed first (D52); `true` unless set.
    zero_buffers: Option<bool>,
    /// The names of the stages, in the order a query goes through them.
    pipeline: Vec<String>,
    /// The stages, by name.
    stages: BTreeMap<String, StageFile>,
}

/// A stage, as written: its settings under its `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum StageFile {
    /// Settings of `dedens_cache::Config`, each defaulting to the RFCs' recommendation.
    Cache(dedens_cache::Config),
    /// Upstream servers, asked in order, each `tries` times waiting `timeout_ms` for a response.
    Forward {
        servers: Vec<Server>,
        timeout_ms: Option<NonZeroU32>,
        tries: Option<NonZeroU8>,
    },
    /// Names and addresses (D54): `entries`, lines in the format of `/etc/hosts`, then those of `file`, read
    /// once at start; each record with `ttl` seconds, 3600 unless set; `fallthrough` passing a listed name's
    /// other types to the next stage.
    Hosts {
        #[serde(default)]
        entries: Vec<String>,
        file: Option<PathBuf>,
        ttl: Option<u32>,
        #[serde(default)]
        fallthrough: bool,
    },
    /// Names blocked with their subdomains (D54): `entries`, one name or a line in the format of `/etc/hosts`
    /// each, then those of `file`, read once at start; answered as `action` says, `nxdomain` unless set, the
    /// addresses of `null` with `ttl` seconds, 3600 unless set.
    Blocklist {
        #[serde(default)]
        entries: Vec<String>,
        file: Option<PathBuf>,
        action: Option<Action>,
        ttl: Option<u32>,
    },
}

/// An upstream server: `IP:PORT`, or an IP address on port 53.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Server(pub(crate) SocketAddr);

impl TryFrom<String> for Server {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        text.parse()
            .or_else(|_| text.parse().map(|ip: IpAddr| SocketAddr::new(ip, 53)))
            .map(Self)
            .map_err(|_| format!("`{text}` is neither IP:PORT nor IP"))
    }
}

/// A configuration ready to serve.
#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) listen: Vec<SocketAddr>,
    pub(crate) zero_buffers: bool,
    pub(crate) pipeline: Pipeline,
}

/// Reads `text`, a configuration file, taking `${VAR}` from `env`.
///
/// # Errors
///
/// A variable without a value, YAML that does not fit the model (an unknown field, a duplicate name), a stage
/// listed but not defined, defined but not listed, listed twice or after a forward stage, which never passes a
/// query on; a second cache stage, which would never be filled; settings a stage refuses.
pub(crate) fn read(text: &str, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<Config> {
    let text = interpolate(text, env)?;
    let file: File = serde_saphyr::from_str(&text)?;
    ensure!(!file.listen.is_empty(), "`listen` has no address");
    ensure!(!file.pipeline.is_empty(), "`pipeline` has no stage");
    let mut stages = file.stages;
    let mut built = Vec::with_capacity(file.pipeline.len());
    for (index, name) in file.pipeline.iter().enumerate() {
        if let Some(Stage::Forward(_)) = built.last() {
            bail!("stage `{name}` comes after a forward stage, which answers every query");
        }
        let Some(stage) = stages.remove(name) else {
            if file.pipeline[..index].contains(name) {
                bail!("stage `{name}` is listed twice in `pipeline`");
            }
            bail!("stage `{name}` is listed in `pipeline` but not defined in `stages`");
        };
        built.push(match stage {
            StageFile::Cache(config) => {
                if built.iter().any(|stage| matches!(stage, Stage::Cache(_))) {
                    bail!("stage `{name}` is a second cache stage, which upstream answers would never fill");
                }
                Stage::Cache(Cache::new(config).with_context(|| format!("stage `{name}`"))?)
            }
            StageFile::Forward {
                servers,
                timeout_ms,
                tries,
            } => {
                let servers: Vec<_> = servers.into_iter().map(|server| server.0).collect();
                let mut forward = Forward::new(&servers)
                    .with_context(|| format!("stage `{name}` has no server"))?;
                if let Some(ms) = timeout_ms {
                    forward = forward.with_timeout(Duration::from_millis(u64::from(ms.get())));
                }
                if let Some(tries) = tries {
                    forward = forward.with_tries(tries);
                }
                Stage::Forward(forward)
            }
            StageFile::Hosts {
                entries,
                file,
                ttl,
                fallthrough,
            } => {
                let ttl = Ttl::from_wire(ttl.unwrap_or(PLUGIN_TTL));
                let hosts = plugin(&entries, file.as_deref(), |text| {
                    Hosts::new(text, ttl, fallthrough)
                })
                .with_context(|| format!("stage `{name}`"))?;
                Stage::Plugin(Box::new(hosts))
            }
            StageFile::Blocklist {
                entries,
                file,
                action,
                ttl,
            } => {
                let ttl = Ttl::from_wire(ttl.unwrap_or(PLUGIN_TTL));
                let blocklist = plugin(&entries, file.as_deref(), |text| {
                    Blocklist::new(text, action.unwrap_or_default(), ttl)
                })
                .with_context(|| format!("stage `{name}`"))?;
                Stage::Plugin(Box::new(blocklist))
            }
        });
    }
    if let Some(name) = stages.keys().next() {
        bail!("stage `{name}` is defined but not listed in `pipeline`");
    }
    Ok(Config {
        listen: file.listen,
        zero_buffers: file.zero_buffers.unwrap_or(true),
        pipeline: Pipeline::new(built),
    })
}

/// The TTL of plugin records unless set, as the hosts plugin of `CoreDNS` gives them.
const PLUGIN_TTL: u32 = 3600;

/// A plugin built by `build` from `entries`, then the lines of the file at `path`; its errors locate the line.
fn plugin<P>(
    entries: &[String],
    path: Option<&Path>,
    build: impl FnOnce(&str) -> Result<P, LineError>,
) -> anyhow::Result<P> {
    let mut text = String::new();
    for entry in entries {
        text.push_str(entry);
        text.push('\n');
    }
    let before = text.lines().count();
    if let Some(path) = path {
        let file =
            fs::read_to_string(path).with_context(|| format!("reading `{}`", path.display()))?;
        text.push_str(&file);
    }
    build(&text).map_err(|error| {
        match (
            error.line.checked_sub(before).filter(|&line| line > 0),
            path,
        ) {
            (Some(line), Some(path)) => anyhow!("`{}` line {line}: {}", path.display(), error.kind),
            _ => anyhow!("entry {}: {}", error.line, error.kind),
        }
    })
}

/// `text` with each `${VAR}` replaced by the variable's value, `${VAR:-default}` by `default` when it is unset or
/// empty, and `$$` by `$`; any other `$` stays.
///
/// # Errors
///
/// A variable without a value or default, one whose value spans lines (it would add YAML of its own), or a `${`
/// left open.
fn interpolate(text: &str, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        if let Some(after) = rest.strip_prefix("$$") {
            out.push('$');
            rest = after;
        } else if let Some(after) = rest.strip_prefix("${") {
            let end = after.find('}').context("a `${` is not closed by `}`")?;
            let (name, default) = match after[..end].split_once(":-") {
                Some((name, default)) => (name, Some(default)),
                None => (&after[..end], None),
            };
            ensure!(
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "`${{{}}}` does not name a variable",
                &after[..end]
            );
            let value = match (env(name).filter(|value| !value.is_empty()), default) {
                (Some(value), _) => value,
                (None, Some(default)) => default.to_owned(),
                (None, None) => bail!("variable `{name}` is not set"),
            };
            ensure!(
                !value.contains('\n'),
                "variable `{name}` spans several lines"
            );
            out.push_str(&value);
            rest = &after[end + 1..];
        } else {
            out.push('$');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str) -> Option<String> {
        match name {
            "PORT" => Some("5353".to_owned()),
            "EMPTY" => Some(String::new()),
            "LINES" => Some("a\nb".to_owned()),
            _ => None,
        }
    }

    fn error(text: &str) -> String {
        format!("{:#}", read(text, env).expect_err("refused"))
    }

    const MINIMAL: &str = "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n";

    #[test]
    fn variables_are_replaced() {
        assert_eq!(interpolate("a ${PORT} b", env).unwrap(), "a 5353 b");
        assert_eq!(interpolate("${NOPE:-53}${EMPTY:-x}", env).unwrap(), "53x");
        assert_eq!(interpolate("$$ $PORT $", env).unwrap(), "$ $PORT $");
    }

    #[test]
    fn variables_without_a_value_are_refused() {
        for (text, message) in [
            ("${NOPE}", "variable `NOPE` is not set"),
            ("${EMPTY}", "variable `EMPTY` is not set"),
            ("${LINES}", "variable `LINES` spans several lines"),
            ("${PORT", "a `${` is not closed by `}`"),
            ("${}", "`${}` does not name a variable"),
            ("${A B}", "`${A B}` does not name a variable"),
        ] {
            let refused = interpolate(text, env).expect_err(text);
            assert_eq!(refused.to_string(), message);
        }
    }

    #[test]
    fn upstream_servers_take_port_53_by_default() {
        let server = |text: &str| Server::try_from(text.to_owned()).map(|server| server.0);
        assert_eq!(server("192.0.2.1"), Ok("192.0.2.1:53".parse().unwrap()));
        assert_eq!(
            server("[2001:db8::1]:5353"),
            Ok("[2001:db8::1]:5353".parse().unwrap())
        );
        assert_eq!(
            server("2001:db8::1"),
            Ok("[2001:db8::1]:53".parse().unwrap())
        );
        assert!(server("example.com").is_err());
    }

    #[test]
    fn a_caching_forwarder_reads() {
        let text = "listen: ['127.0.0.1:${PORT}']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n    max_ttl: 3600\n    stale_answer_after_ms: 0\n  up:\n    type: forward\n    servers: ['192.0.2.1', '192.0.2.2:5353']\n    timeout_ms: 500\n    tries: 1\n";
        let config = read(text, env).unwrap();
        assert_eq!(config.listen, ["127.0.0.1:5353".parse().unwrap()]);
        assert!(read(MINIMAL, env).is_ok());
    }

    #[test]
    fn buffers_are_zeroed_unless_set_not_to() {
        assert!(read(MINIMAL, env).unwrap().zero_buffers);
        let text = format!("zero_buffers: false\n{MINIMAL}");
        assert!(!read(&text, env).unwrap().zero_buffers);
    }

    #[test]
    fn mistakes_are_errors() {
        for (text, message) in [
            (
                "listen: []\npipeline: [up]\nstages: {}\n",
                "`listen` has no address",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: []\nstages: {}\n",
                "`pipeline` has no stage",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages: {}\n",
                "stage `up` is listed in `pipeline` but not defined in `stages`",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c, c]\nstages:\n  c:\n    type: cache\n",
                "stage `c` is listed twice in `pipeline`",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c, d]\nstages:\n  c:\n    type: cache\n  d:\n    type: cache\n",
                "stage `d` is a second cache stage, which upstream answers would never fill",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [up, c]\nstages:\n  c:\n    type: cache\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                "stage `c` comes after a forward stage, which answers every query",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  c:\n    type: cache\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                "stage `c` is defined but not listed in `pipeline`",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: []\n",
                "stage `up` has no server",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    shards: 3\n",
                "stage `c`: the shard count must be a power of two up to 65536, not 3",
            ),
        ] {
            assert_eq!(error(text), message);
        }
    }

    /// A hosts stage before the forward stage: entries, then a file, its lines counted from its first.
    #[test]
    fn hosts_read_entries_then_their_file() {
        let path = std::env::temp_dir().join(format!("dedensd-hosts-{}", std::process::id()));
        let stage = |file: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [hosts, up]\nstages:\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 printer.lan', '{{ENTRY}}']\n    file: {}\n    ttl: 60\n    fallthrough: true\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                path.join(file).display()
            )
        };
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("good"), "127.0.0.1 localhost\n").unwrap();
        std::fs::write(
            path.join("bad"),
            "# fine\n127.0.0.1 localhost\nnope localhost\n",
        )
        .unwrap();
        let ok = stage("good").replace("{ENTRY}", "192.0.2.2 scanner.lan");
        assert!(read(&ok, env).is_ok());
        for (text, message) in [
            (
                stage("bad").replace("{ENTRY}", "192.0.2.2 scanner.lan"),
                "line 3: `nope` is not an IP address",
            ),
            (
                stage("good").replace("{ENTRY}", "192.0.2.2"),
                "entry 2: an address without a name",
            ),
            (
                stage("none").replace("{ENTRY}", "192.0.2.2 scanner.lan"),
                "reading",
            ),
        ] {
            let message_read = error(&text);
            assert!(message_read.contains(message), "{message}: {message_read}");
        }
        std::fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn blocklists_read_their_action() {
        let text = |action: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [block, up]\nstages:\n  block:\n    type: blocklist\n    entries: [ads.example, '0.0.0.0 tracker.example']\n{action}  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
            )
        };
        for action in [
            "",
            "    action: nxdomain\n",
            "    action: null\n    ttl: 60\n",
        ] {
            assert!(read(&text(action), env).is_ok(), "{action}");
        }
        assert!(error(&text("    action: drop\n")).contains("drop"));
    }

    #[test]
    fn yaml_outside_the_model_is_refused() {
        for (text, needle) in [
            (format!("{MINIMAL}threads: 2\n"), "threads"),
            (MINIMAL.replace("servers:", "upstreams:"), "upstreams"),
            (MINIMAL.replace("forward", "rewrite"), "rewrite"),
            (format!("{MINIMAL}  up:\n    type: cache\n"), "up"),
            ("listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    size: 1\n".to_owned(), "size"),
            (MINIMAL.replace("192.0.2.1", "example.com"), "example.com"),
            (format!("{MINIMAL}    tries: 0\n"), "nonzero"),
            (format!("{MINIMAL}    timeout_ms: 0\n"), "nonzero"),
        ] {
            let message = error(&text);
            assert!(message.contains(needle), "{needle}: {message}");
        }
    }
}
