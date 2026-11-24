//! An `authoritative` stage, as written and built (D208): the zones it serves, each a name and the file holding it
//! in the presentation format (RFC 1035 §5), kept across reloads while their files stay (D120), and its access
//! lists: who may transfer it, notify the server or update it, by network and TSIG key (D211).

use std::path::PathBuf;

use anyhow::{Context as _, bail, ensure};
use dedens_proto::{Name, Question, RecordType};
use dedens_server::{Action, Authoritative, Grant, Network, Stage, ZoneAccess};
use dedens_zone::End;
use serde::Deserialize;

use super::tsig::Keys;
use crate::lists::Store;

/// The most zones an `authoritative` stage serves: 10 000 (D115). Each is a file read and stamped at every reload
/// (D120), and a line of the configuration; past that, a catalog of zones (RFC 9432) is the tool, which the
/// configuration lacks. Knot, NSD and BIND bound none: NSD serves millions from its `zonelist`, added at run time.
pub(super) const MAX_ZONES: usize = 10_000;

/// The most networks an access list of a zone holds, its lines together: 1000 (D115). A transfer, NOTIFY or
/// UPDATE walks them all; a zone has a few secondaries, primaries and updaters. Knot, NSD and BIND bound none.
pub(super) const MAX_LIST_NETWORKS: usize = 1000;

/// An `authoritative` stage's settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthoritativeFile {
    zones: Vec<ZoneFile>,
}

/// A zone, as written: its apex, `name`, and the `file` it is read from; `$INCLUDE` reads files in the directory of
/// `file` or below it. Its access lists permit nothing unless written (RFC 5936 §5).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneFile {
    name: Domain,
    file: PathBuf,
    /// Who may transfer the zone, AXFR or IXFR.
    #[serde(default)]
    transfer: Vec<GrantFile>,
    /// Who may notify the server of a change to the zone.
    #[serde(default)]
    notify: Vec<GrantFile>,
    /// Who may update the zone.
    #[serde(default)]
    update: Vec<GrantFile>,
}

/// A line of an access list, as written: the clients in one of `networks` whose requests are signed with `key`,
/// one of `keys`, or unsigned without it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantFile {
    networks: Vec<Network>,
    key: Option<Domain>,
}

/// A domain name in presentation format: a zone's apex, a key's name.
#[derive(Debug, Deserialize)]
#[serde(try_from = "String")]
pub(super) struct Domain(pub(super) Name<'static>);

impl TryFrom<String> for Domain {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        text.parse()
            .map(Self)
            .map_err(|error| format!("`{text}` is not a name: {error}"))
    }
}

/// The `authoritative` stage `name` of `file`, its zones from `store`, the keys of its access lists from `keys`.
///
/// # Errors
///
/// No zone, or more than [`MAX_ZONES`]; a zone given twice; a zone that does not load, at the start or new to the
/// configuration (a zone served keeps its last version, D55); an access list line without a network or with a key
/// not in `keys`, a list of more than [`MAX_LIST_NETWORKS`] networks.
pub(super) fn authoritative(
    name: &str,
    file: &AuthoritativeFile,
    keys: &Keys,
    store: &mut Store,
) -> anyhow::Result<Stage> {
    let count = file.zones.len();
    ensure!(count > 0, "stage `{name}`: `zones` is empty");
    ensure!(
        count <= MAX_ZONES,
        "stage `{name}`: `zones` lists {count} zones, over {MAX_ZONES}"
    );
    let (zones, histories): (Vec<_>, Vec<_>) = (file.zones.iter())
        .map(|zone| {
            let context = || format!("stage `{name}`, zone `{}`", zone.name.0);
            let access = access(zone, keys).with_context(context)?;
            let loaded = store.zones.zone(&zone.name.0, &zone.file);
            let history = store.zones.history(&zone.name.0, &zone.file);
            Ok((
                (loaded.with_context(context)?, access),
                (&zone.name.0, history),
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .unzip();
    let stage = Authoritative::guarded(zones).with_context(|| format!("stage `{name}`"))?;
    let stage = (histories.into_iter()).fold(stage, |stage, (apex, history)| {
        stage.with_history(apex, history)
    });
    warn_undelegated(&stage);
    Ok(Stage::Authoritative(stage))
}

/// The access lists of `zone`, their keys from `keys`.
fn access(zone: &ZoneFile, keys: &Keys) -> anyhow::Result<ZoneAccess> {
    let lists = [
        (Action::Transfer, "transfer", &zone.transfer),
        (Action::Notify, "notify", &zone.notify),
        (Action::Update, "update", &zone.update),
    ];
    lists
        .into_iter()
        .try_fold(ZoneAccess::default(), |access, (action, setting, list)| {
            let networks: usize = list.iter().map(|grant| grant.networks.len()).sum();
            ensure!(
                networks <= MAX_LIST_NETWORKS,
                "`{setting}` lists {networks} networks, over {MAX_LIST_NETWORKS}"
            );
            let grants = list
                .iter()
                .map(|grant| {
                    ensure!(
                        !grant.networks.is_empty(),
                        "`{setting}`: a line has no network"
                    );
                    let key = match &grant.key {
                        None => None,
                        Some(name) => match keys.ring.get(&name.0) {
                            Some(key) => Some(key),
                            None if keys.skipped(&name.0) => bail!(
                                "`{setting}`: key `{}` is not read: a key added or changed takes a restart",
                                name.0
                            ),
                            None => bail!("`{setting}`: key `{}` is not in `keys`", name.0),
                        },
                    };
                    Ok(Grant::new(grant.networks.iter().copied(), key))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(access.with(action, grants))
        })
}

/// Warns of each zone served below another that has no NS at its apex: the parent denies the child's apex, and
/// the names below, to a client that asks it for them, as NXDOMAIN, which RFC 8020 resolvers cache for the whole
/// subtree. Knot answers so; NSD answers NODATA from its shared tree (D208).
fn warn_undelegated(stage: &Authoritative) {
    for zone in stage.zones() {
        let Some(parent) = (zone.apex().parent()).and_then(|parent| stage.zone(&parent)) else {
            continue;
        };
        let question = Question::new(zone.apex().clone(), RecordType::NS);
        if !matches!(parent.answer(&question).end, End::Referral { .. }) {
            tracing::warn!(
                zone = %zone.apex(),
                parent = %parent.apex(),
                "zone served below a zone with no NS at its apex: the parent does not delegate it"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    use dedens_proto::Message;
    use dedens_server::{Pipeline, VerifiedKey};
    use dedens_tsig::Keyring;

    use super::super::tests::env;
    use super::super::unix_seconds;
    use super::*;

    /// A configuration of an authoritative stage alone, serving `zones`, each a name and a file.
    fn serving(zones: &[(&str, &Path)]) -> String {
        let mut text = String::from(
            "listen: ['127.0.0.1:53']\npipeline: [zones]\nstages:\n  zones:\n    type: authoritative\n    zones:\n",
        );
        for (name, file) in zones {
            writeln!(text, "      - {{name: {name}, file: {}}}", file.display()).unwrap();
        }
        text
    }

    fn read(text: &str, store: &mut Store) -> anyhow::Result<Pipeline> {
        crate::config::read(text, env, (&Pipeline::default(), None), store)
            .map(|config| config.pipeline)
    }

    /// The zone of RFC 4035 Appendix A, copied to `dir`.
    fn example(dir: &Path) -> PathBuf {
        let path = dir.join("example.zone");
        fs::copy(dedens_testkit::path("zones/rfc4035_appendix_a.zone"), &path).unwrap();
        path
    }

    #[test]
    fn the_zones_listed_are_served() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let pipeline = read(&serving(&[("example", &path)]), &mut Store::default()).unwrap();
        let [Stage::Authoritative(stage)] = pipeline.stages() else {
            panic!("{:?}", pipeline.stages());
        };
        let apexes: Vec<_> = stage
            .zones()
            .iter()
            .map(|zone| zone.apex().to_string())
            .collect();
        assert_eq!(apexes, ["example."]);
    }

    #[test]
    fn mistakes_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let error = |text: &str| format!("{:#}", read(text, &mut Store::default()).unwrap_err());
        let empty = serving(&[]).replace("    zones:\n", "    zones: []\n");
        assert!(
            error(&empty).contains("`zones` is empty"),
            "{}",
            error(&empty)
        );
        let twice = serving(&[("example", &path), ("EXAMPLE.", &path)]);
        assert!(
            error(&twice).contains("zone `example.` is given twice"),
            "{}",
            error(&twice)
        );
        let missing = serving(&[("example", &dir.path().join("missing.zone"))]);
        assert!(
            error(&missing).contains("stage `zones`, zone `example.`"),
            "{}",
            error(&missing)
        );
        // The SOA of the file is at `example.`: the zone of another name has none.
        let other = serving(&[("example.org", &path)]);
        assert!(
            error(&other).contains("zone `example.org.`"),
            "{}",
            error(&other)
        );
        let bad = serving(&[("exa..mple", &path)]);
        assert!(error(&bad).contains("is not a name"), "{}", error(&bad));
        let unknown = serving(&[("example", &path)]).replace(
            "    zones:\n",
            "    zones:\n      - {name: x, file: x.zone, ttl: 1}\n",
        );
        assert!(
            error(&unknown).contains("unknown field `ttl`"),
            "{}",
            error(&unknown)
        );
    }

    #[test]
    fn at_most_max_zones() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let names: Vec<String> = (0..=MAX_ZONES).map(|n| format!("z{n}.example")).collect();
        let zones: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), path.as_path()))
            .collect();
        let error = format!(
            "{:#}",
            read(&serving(&zones), &mut Store::default()).unwrap_err()
        );
        assert!(error.contains(&format!("over {MAX_ZONES}")), "{error}");
    }

    /// [`serving`] `example` from `path` with `keys` and the zone's access lists `lists`, a key file of the captures'
    /// secret (D203) written to `dir` as `secret.key`, once: a file written again is a file changed (D211).
    fn guarded(dir: &Path, path: &Path, keys: &str, lists: &str) -> String {
        let secret = dir.join("secret.key");
        if !secret.exists() {
            private(&secret, dedens_testkit::authoritative::TSIG_KEY.secret);
        }
        let keys = keys.replace("SECRET", &secret.display().to_string());
        format!(
            "{keys}listen: ['127.0.0.1:53']\npipeline: [zones]\nstages:\n  zones:\n    type: authoritative\n    zones:\n      - name: example\n        file: {}\n{lists}",
            path.display()
        )
    }

    /// Writes `text` to `path`, readable by its owner alone (D115).
    fn private(path: &Path, text: &str) {
        fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// The key of the captures (D203) named `name`, of `algorithm`.
    fn key(name: &str, algorithm: &str) -> dedens_tsig::Key {
        let secret = dedens_testkit::authoritative::TSIG_KEY.secret;
        dedens_tsig::Key::from_base64(name.parse().unwrap(), algorithm.parse().unwrap(), secret)
            .unwrap()
    }

    /// The key `name` of `pipeline`, of a request signed with it now and verified: the one way to get a
    /// `VerifiedKey`.
    fn verified<'p>(pipeline: &'p Pipeline, name: &str) -> VerifiedKey<'p> {
        let query = Message::query(7, Question::new(name.parse().unwrap(), RecordType::SOA));
        let mut request = query.to_vec().unwrap();
        let key = key(name, "hmac-sha256");
        dedens_tsig::sign_request(&key, &mut request, unix_seconds()).unwrap();
        pipeline.verified_key(&request).unwrap()
    }

    /// D211: the keys are read from their files, the access lists of a zone built with them, a line of a key
    /// permitting requests signed with it alone, a line without one unsigned requests alone.
    #[test]
    fn keys_and_access_lists_are_built() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let keys = "keys:\n  - {name: Secondary, algorithm: HMAC-SHA256, secret_file: SECRET}\n";
        let lists = "        transfer:\n          - {networks: ['192.0.2.0/24'], key: secondary.}\n        notify:\n          - {networks: ['2001:db8::/32']}\n";
        let pipeline = read(
            &guarded(dir.path(), &path, keys, lists),
            &mut Store::default(),
        )
        .unwrap();
        assert_eq!(pipeline.keys().map(Keyring::len), Some(1));
        let [Stage::Authoritative(stage)] = pipeline.stages() else {
            panic!("{:?}", pipeline.stages());
        };
        let (_, access) = stage.access(&"www.example.".parse().unwrap()).unwrap();
        let other = Pipeline::default().with_keys(
            Keyring::new([key("other", "hmac-sha256")]).unwrap(),
            Arc::new(unix_seconds),
        );
        let secondary = verified(&pipeline, "secondary");
        let inside = "192.0.2.7".parse().unwrap();
        assert!(access.permits(Action::Transfer, inside, Some(secondary)));
        assert!(!access.permits(Action::Transfer, inside, None));
        assert!(!access.permits(Action::Transfer, inside, Some(verified(&other, "other"))));
        assert!(!access.permits(
            Action::Transfer,
            "198.51.100.1".parse().unwrap(),
            Some(secondary)
        ));
        let primary = "2001:db8::53".parse().unwrap();
        assert!(access.permits(Action::Notify, primary, None));
        assert!(!access.permits(Action::Notify, primary, Some(secondary)));
        assert!(!access.permits(Action::Update, primary, None));
    }

    /// D211: the access lists and the keys refuse what they cannot honour.
    #[test]
    fn access_list_and_key_mistakes_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let key = "keys:\n  - {name: k, algorithm: hmac-sha256, secret_file: SECRET}\n";
        let error = |keys: &str, lists: &str| {
            let text = guarded(dir.path(), &path, keys, lists);
            format!("{:#}", read(&text, &mut Store::default()).unwrap_err())
        };
        let cases = [
            (
                key,
                "        transfer:\n          - {networks: ['192.0.2.0/24'], key: j}\n",
                "key `j.` is not in `keys`",
            ),
            (
                key,
                "        update:\n          - {networks: []}\n",
                "`update`: a line has no network",
            ),
            (
                key,
                "        notify:\n          - {networks: ['192.0.2.1/24']}\n",
                "bits set past",
            ),
            (
                key,
                "        notify:\n          - {network: ['192.0.2.0/24']}\n",
                "unknown field `network`",
            ),
            (
                "keys:\n  - {name: k, algorithm: hmac-md5, secret_file: SECRET}\n",
                "",
                "unknown TSIG algorithm",
            ),
            (
                "keys:\n  - {name: k, algorithm: hmac-sha256, secret_file: SECRET}\n  - {name: K., algorithm: hmac-sha1, secret_file: SECRET}\n",
                "",
                "two TSIG keys are named K.",
            ),
            (
                "keys:\n  - {name: k, algorithm: hmac-sha256, secret_file: /nonexistent/k.key}\n",
                "",
                "cannot read the key",
            ),
        ];
        for (keys, lists, expected) in cases {
            let error = error(keys, lists);
            assert!(error.contains(expected), "{expected}: {error}");
        }
        // Not base64, without echoing the secret.
        let secret = dir.path().join("garbled.key");
        private(&secret, "not*base64*secret");
        let garbled = format!(
            "keys:\n  - {{name: k, algorithm: hmac-sha256, secret_file: {}}}\n",
            secret.display()
        );
        let refused = error(&garbled, "");
        assert!(refused.contains("holds no secret in base64"), "{refused}");
        assert!(!refused.contains("not*base64"), "{refused}");
        // Longer than the most a file holds.
        private(&secret, &"A".repeat(1025));
        let long = error(&garbled, "");
        assert!(long.contains("is longer than 1024 bytes"), "{long}");
        // Keys where no zone signs.
        let text = format!(
            "{key}{}",
            serving(&[]).replace("type: authoritative\n    zones:\n", "type: cache\n")
        );
        let text = text.replace(
            "SECRET",
            &dir.path().join("secret.key").display().to_string(),
        );
        let error = format!("{:#}", read(&text, &mut Store::default()).unwrap_err());
        assert!(
            error.contains("`keys` needs an authoritative stage"),
            "{error}"
        );
    }

    /// D211, D115: at most [`MAX_LIST_NETWORKS`] networks a list, [`super::super::tsig::MAX_KEYS`] keys.
    #[test]
    fn at_most_max_list_networks_and_max_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let networks: Vec<String> = (0..=MAX_LIST_NETWORKS)
            .map(|n| format!("'10.{}.{}.0/24'", n / 256, n % 256))
            .collect();
        let lists = format!(
            "        transfer:\n          - {{networks: [{}]}}\n",
            networks.join(", ")
        );
        let text = guarded(dir.path(), &path, "", &lists);
        let error = format!("{:#}", read(&text, &mut Store::default()).unwrap_err());
        assert!(
            error.contains(&format!("over {MAX_LIST_NETWORKS}")),
            "{error}"
        );
        // The bound itself is accepted.
        let lists = lists.replacen("'10.0.0.0/24', ", "", 1);
        read(
            &guarded(dir.path(), &path, "", &lists),
            &mut Store::default(),
        )
        .unwrap();

        let most = super::super::tsig::MAX_KEYS;
        let mut keys = String::from("keys:\n");
        for n in 0..=most {
            writeln!(
                keys,
                "  - {{name: k{n}, algorithm: hmac-sha256, secret_file: SECRET}}"
            )
            .unwrap();
        }
        let error = format!(
            "{:#}",
            read(
                &guarded(dir.path(), &path, &keys, ""),
                &mut Store::default()
            )
            .unwrap_err()
        );
        assert!(error.contains(&format!("over {most}")), "{error}");
    }

    /// D211, D122: the key files are read at start only; a reload, or the build after the privileges are dropped,
    /// keeps the keys read then while their files are as they were, and revokes them when a file cannot be stat.
    #[test]
    fn the_keys_read_at_start_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let keys = "keys:\n  - {name: k, algorithm: hmac-sha256, secret_file: SECRET}\n";
        let lists = "        transfer:\n          - {networks: ['192.0.2.0/24'], key: k}\n";
        let text = guarded(dir.path(), &path, keys, lists);
        let mut store = Store::default();
        let started = read(&text, &mut store).unwrap();
        let reloaded = crate::config::read(&text, env, (&started, Some(1)), &mut store)
            .unwrap()
            .pipeline;
        let k = reloaded
            .keys()
            .and_then(|keys| keys.get(&"k.".parse().unwrap()));
        assert_eq!(
            k.map(dedens_tsig::Key::algorithm),
            Some(dedens_tsig::Algorithm::HmacSha256)
        );
        // A key added on reload is not read: the line naming it is an error.
        let keys =
            format!("{keys}  - {{name: j, algorithm: hmac-sha256, secret_file: /nonexistent}}\n");
        let added = guarded(
            dir.path(),
            &path,
            &keys,
            &lists.replace("key: k}", "key: j}"),
        );
        let error = crate::config::read(&added, env, (&started, Some(1)), &mut store).unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("key `j.` is not read: a key added or changed takes a restart"),
            "{error:#}"
        );
        // The file gone, so that it cannot be stat: the key is revoked, the fail-safe; a line naming it is refused.
        fs::remove_file(dir.path().join("secret.key")).unwrap();
        let error = crate::config::read(&text, env, (&started, Some(1)), &mut store).unwrap_err();
        assert!(
            format!("{error:#}").contains("key `k.` is not read"),
            "{error:#}"
        );
    }

    /// D211: a reload keeps the keys of the file that it still names, with their algorithm and secret file, and
    /// revokes the others; a line naming a key revoked is an error, as one naming a key added.
    #[test]
    fn a_reload_revokes_the_keys_it_drops() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let both = "keys:\n  - {name: k, algorithm: hmac-sha256, secret_file: SECRET}\n  - {name: j, algorithm: hmac-sha256, secret_file: SECRET}\n";
        let granting = |key: &str| {
            format!("        transfer:\n          - {{networks: ['192.0.2.0/24'], key: {key}}}\n")
        };
        let mut store = Store::default();
        let text = guarded(dir.path(), &path, both, &granting("k"));
        // `other.key` is the same file as `secret.key`, so that only its path tells it from the one read.
        fs::hard_link(dir.path().join("secret.key"), dir.path().join("other.key")).unwrap();
        let started = read(&text, &mut store).unwrap();
        assert_eq!(started.keys().map(Keyring::len), Some(2));
        let reload = |text: &str, store: &mut Store| {
            crate::config::read(text, env, (&started, Some(1)), store).map(|config| config.pipeline)
        };
        let names = |pipeline: &Pipeline| {
            let keys = pipeline.keys().unwrap();
            ["k.", "j."].map(|name| keys.get(&name.parse().unwrap()).is_some())
        };
        // The same keys, in another order and case: all kept.
        let same = "keys:\n  - {name: J, algorithm: HMAC-SHA256, secret_file: SECRET}\n  - {name: k, algorithm: hmac-sha256, secret_file: SECRET}\n";
        let text = guarded(dir.path(), &path, same, &granting("k"));
        assert_eq!(names(&reload(&text, &mut store).unwrap()), [true, true]);
        // Without `k`: revoked, `j` kept; a line naming `k` is refused.
        let only_j = "keys:\n  - {name: j, algorithm: hmac-sha256, secret_file: SECRET}\n";
        let text = guarded(dir.path(), &path, only_j, &granting("j"));
        assert_eq!(names(&reload(&text, &mut store).unwrap()), [false, true]);
        let text = guarded(dir.path(), &path, only_j, &granting("k"));
        let error = reload(&text, &mut store).unwrap_err();
        assert!(
            format!("{error:#}").contains("key `k.` is not in `keys`"),
            "{error:#}"
        );
        // Another algorithm, or another secret file: changed, so not read, and dropped.
        let sha512 = only_j.replace("hmac-sha256", "hmac-sha512");
        let text = guarded(dir.path(), &path, &sha512, "");
        assert_eq!(names(&reload(&text, &mut store).unwrap()), [false, false]);
        let moved = only_j.replace(
            "SECRET",
            &dir.path().join("other.key").display().to_string(),
        );
        let text = guarded(dir.path(), &path, &moved, "");
        assert_eq!(names(&reload(&text, &mut store).unwrap()), [false, false]);
        // The secret file rewritten in place, the same path: changed, so not read, and dropped.
        let text = guarded(dir.path(), &path, same, "");
        assert_eq!(names(&reload(&text, &mut store).unwrap()), [true, true]);
        private(
            &dir.path().join("secret.key"),
            "b3RoZXIgc2VjcmV0IG9mIHRoaXJ0eS10d28gYnl0ZXM=",
        );
        assert_eq!(names(&reload(&text, &mut store).unwrap()), [false, false]);
        // No `keys` at all: every key revoked.
        let text = guarded(dir.path(), &path, "", "");
        assert_eq!(
            reload(&text, &mut store).unwrap().keys().map(Keyring::len),
            Some(0)
        );
    }

    /// D211: a reload that leaves the authoritative stage, and the `keys` with it, is a forwarder; `keys` left in
    /// the file without the stage are refused.
    #[test]
    fn a_reload_may_drop_the_authoritative_stage_and_the_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let keys = "keys:\n  - {name: k, algorithm: hmac-sha256, secret_file: SECRET}\n";
        let mut store = Store::default();
        let started = read(&guarded(dir.path(), &path, keys, ""), &mut store).unwrap();
        assert_eq!(started.keys().map(Keyring::len), Some(1));
        let forwarder = |keys: &str| {
            let text = format!(
                "{keys}listen: ['127.0.0.1:53']\npipeline: [cache]\nstages:\n  cache: {{type: cache}}\n"
            );
            let text = text.replace(
                "SECRET",
                &dir.path().join("secret.key").display().to_string(),
            );
            crate::config::read(&text, env, (&started, Some(1)), &mut Store::default())
        };
        assert!(forwarder("").unwrap().pipeline.keys().is_none());
        let error = forwarder(keys).map(|_| ()).unwrap_err();
        assert!(
            format!("{error:#}").contains("`keys` needs an authoritative stage"),
            "{error:#}"
        );
    }

    #[test]
    fn the_authoritative_stage_comes_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = example(dir.path());
        let text = serving(&[("example", &path)])
            .replace("pipeline: [zones]", "pipeline: [hosts, zones]")
            + "  hosts:\n    type: hosts\n    entries: ['192.0.2.1 a.test']\n";
        let error = format!("{:#}", read(&text, &mut Store::default()).unwrap_err());
        assert!(error.contains("stage `zones` comes after"), "{error}");
    }
}
