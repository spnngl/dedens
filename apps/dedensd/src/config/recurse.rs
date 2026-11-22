//! A `recurse` stage, as written and built (D195): the resolution's limits (D191) and whether it asks servers at
//! special-purpose addresses (`query_local_addresses`, D191), its QNAME minimisation (D198), whether it answers
//! from the NSEC and NSEC3 records cached (`aggressive_nsec`, D199),
//! the zones served locally to resolve instead (RFC 6303 §3), a client network's share of the queries (D117), the
//! sizes of its caches (D193, D194), and its validation (D197), set as a forward stage's (D77). A reload keeps its
//! caches while their sizes, the cache stage's settings and the validation stay, and the share's buckets while its
//! budget stays.

use std::fs;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use dedens_dnssec::TrustAnchors;
use dedens_proto::Name;
use dedens_resolver::{
    Caches, DEFAULT_CAPACITY, InfraCache, Limits, Minimisation, RrsetCache, askable,
};
use dedens_roots::{RootHints, Server, Tlds};
use dedens_server::{Allowance, Budgets, DEFAULT_SHARE, Pipeline, Recurse, Stage, Validating};
use serde::Deserialize;

use super::limits::BudgetFile;
use super::upstream::{Dnssec, Insecure, Validation};

/// A `recurse` stage's settings.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecurseFile {
    #[serde(default)]
    limits: LimitsFile,
    #[serde(default)]
    qname_minimisation: MinimisationFile,
    #[serde(default)]
    local_zones: LocalZonesFile,
    /// Whether servers at loopback, private and the other special-purpose addresses are asked:
    /// `Recurse::asking_local_addresses`.
    #[serde(default)]
    query_local_addresses: bool,
    /// Whether the secure NSEC and NSEC3 records cached answer the names they prove absent, on unless `false`:
    /// `Recurse::aggressive_nsec` (RFC 8198, D199).
    aggressive_nsec: Option<bool>,
    client_share: Option<BudgetFile>,
    rrset_cache_bytes: Option<NonZeroUsize>,
    infra_cache_bytes: Option<NonZeroUsize>,
    /// A file of root hints (zone text, as `named.root`) in place of the bundled ones, for a private root (D201);
    /// with it the TLD hints are not used either, as they are the public Internet's.
    root_hints: Option<PathBuf>,
    /// Whether it validates: `validate` unless written, where a forward stage's is `off` (D77, D197).
    dnssec: Option<Dnssec>,
    trust_anchors: Option<PathBuf>,
    #[serde(default)]
    insecure: Vec<Insecure>,
}

impl RecurseFile {
    /// Whether building it reads a file it names: its trust anchors or root hints.
    pub(super) const fn names_files(&self) -> bool {
        self.trust_anchors.is_some() || self.root_hints.is_some()
    }

    /// Whether it validates (D197): `validate` unless `dnssec` is written.
    fn dnssec(&self) -> Dnssec {
        self.dnssec.unwrap_or(Dnssec::Validate)
    }

    /// Whether it validates, read before its trust anchors move into [`Validation`].
    pub(super) fn validates_by_root(&self) -> bool {
        matches!(self.dnssec(), Dnssec::Validate) && self.trust_anchors.is_none()
    }
}

/// The bounds of one resolution, each `Limits::default`'s unless written.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    queries: Option<NonZeroUsize>,
    restarts: Option<NonZeroUsize>,
    referrals: Option<NonZeroUsize>,
    depth: Option<NonZeroUsize>,
    servers: Option<NonZeroUsize>,
    targets: Option<NonZeroUsize>,
    validation: Option<NonZeroUsize>,
    time_ms: Option<NonZeroU32>,
}

/// The most each count of `limits` may be set to: the highest BIND or Unbound allows or uses, or BIND's default
/// where BIND sets no maximum, so that no setting lets one client question cost what neither would by default
/// (D195).
const MAX: Limits = Limits {
    // BIND's `max-query-count` default 200 (`bin/include/defaultconfig.h`), not a maximum: the queries of a client
    // question, validation's included.
    queries: 200,
    // BIND's `max-query-restarts` range, 1 to 255.
    restarts: 255,
    // Unbound's `MAX_REFERRAL_COUNT` 130 (`iterator/iterator.h`).
    referrals: 130,
    // BIND's `max-recursion-depth` default 7 (`bin/include/defaultconfig.h`), not a maximum.
    depth: 7,
    // BIND's `max-delegation-servers` range, 1 to 100.
    servers: 100,
    // Unbound's `MAX_DP_TARGET_COUNT` 16 (`iterator/iterator.h`).
    targets: 16,
    // Unbound's `MAX_GLOBAL_QUOTA` 200 (`iterator/iterator.h`), the queries of a client question with its validation's.
    validation: 200,
    // A client gives up well before, and a resolution holds one of the thread's upstream queries (D47) all along.
    time: Duration::from_secs(30),
};

/// How much of the names asked the servers see (RFC 9156, D198).
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MinimisationFile {
    #[default]
    Relaxed,
    Strict,
    /// `none`: YAML reads `off` as the boolean false.
    None,
}

impl From<MinimisationFile> for Minimisation {
    fn from(file: MinimisationFile) -> Self {
        match file {
            MinimisationFile::Relaxed => Self::Relaxed,
            MinimisationFile::Strict => Self::Strict,
            MinimisationFile::None => Self::Off,
        }
    }
}

/// The zones served locally, all of them unless listed in `resolve`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalZonesFile {
    #[serde(default)]
    resolve: Vec<String>,
}

/// The stage `name` of `file`, after the stages `built`: its TTLs bounded as their cache stage's, if any; its caches
/// those of `previous`'s recurse stage when their sizes and settings are the same, and it validates the same way:
/// the `RRset` cache holds the verdicts of its validator (D197). Validating, its anchors are the root's of `root`
/// (D128) unless `trust_anchors` names some, and its allowance `allowance` (D77).
///
/// # Errors
///
/// A limit above [`MAX`]'s; a `root_hints` file that does not read, holds no root server, or none at an address
/// asked (D191: every query would fail, unless `query_local_addresses` is set); a zone in `local_zones.resolve`
/// that is not a name, not served locally or listed twice; a `client_share` [`Budgets::new`] refuses; caches
/// [`RrsetCache::new`] or [`InfraCache::new`] refuses; validation settings [`Validation::validating`] refuses.
pub(super) fn recurse(
    name: &str,
    file: RecurseFile,
    (built, previous): (&[Stage], &Pipeline),
    (root, allowance): (Option<TrustAnchors>, Allowance),
) -> anyhow::Result<Stage> {
    let validation = Validation {
        dnssec: file.dnssec(),
        trust_anchors: file.trust_anchors,
        root,
        insecure: file.insecure,
        // The stage's `client_share` is of the queries sent (D117): validation's is the default.
        client_share: None,
        allowance,
    };
    let held = previous.stages().iter().filter_map(|stage| match stage {
        Stage::Recurse(old) => old.validation(),
        _ => None,
    });
    let validating = validation.validating(name, held)?;
    let tag = validating.as_ref().map(Validating::tag);
    // The TTLs the cache stage stores under, which the stage answers under too.
    let cache = (built.iter())
        .find_map(|stage| match stage {
            Stage::Cache(cache) => Some(cache.config().clone()),
            _ => None,
        })
        .unwrap_or_default();
    let cache = &cache;
    let context = || format!("stage `{name}`");
    let limits = limits(file.limits).with_context(context)?;
    let rrset_bytes = file
        .rrset_cache_bytes
        .map_or(DEFAULT_CAPACITY, NonZeroUsize::get);
    let infra_bytes =
        (file.infra_cache_bytes).map_or(InfraCache::DEFAULT_CAPACITY, NonZeroUsize::get);
    let (roots, tlds) = match file.root_hints {
        Some(path) => (
            read_hints(&path, file.query_local_addresses)
                .with_context(|| format!("stage `{name}`: `root_hints`"))?,
            None,
        ),
        None => (RootHints::bundled().clone(), Some(Tlds::bundled().clone())),
    };
    let kept = previous.stages().iter().find_map(|stage| match stage {
        Stage::Recurse(held) => {
            let caches = held.caches();
            let same = caches.rrsets.capacity() == rrset_bytes
                && caches.infra.capacity() == infra_bytes
                && caches.roots == roots
                && caches.tlds.is_some() == tlds.is_some()
                && caches.rrsets.config() == cache
                && held.validation_tag() == tag;
            same.then(|| Arc::clone(caches))
        }
        _ => None,
    });
    let caches = match kept {
        Some(caches) => caches,
        None => Arc::new(Caches {
            rrsets: RrsetCache::new(rrset_bytes, cache.clone())
                .with_context(|| format!("stage `{name}`: `rrset_cache_bytes`"))?,
            infra: InfraCache::new(infra_bytes, cache.shards)
                .with_context(|| format!("stage `{name}`: `infra_cache_bytes`"))?,
            roots,
            tlds,
        }),
    };
    let share = BudgetFile::over(file.client_share, DEFAULT_SHARE);
    // The buckets of the same budget are kept, what each network spent with them: a reload is no fresh burst.
    let kept = previous.stages().iter().find_map(|stage| match stage {
        Stage::Recurse(held) => held.share().filter(|held| held.config() == share).cloned(),
        _ => None,
    });
    let share = match kept {
        Some(share) => share,
        None => Arc::new(
            Budgets::new(share).with_context(|| format!("stage `{name}`: `client_share`"))?,
        ),
    };
    let mut stage = Recurse::new(caches)
        .with_limits(limits)
        .asking_local_addresses(file.query_local_addresses)
        .aggressive_nsec(file.aggressive_nsec.unwrap_or(true))
        .with_minimisation(file.qname_minimisation.into())
        .with_share(share);
    if let Some(validating) = validating {
        stage = stage.validating(validating);
    }
    let mut resolved: Vec<Name<'static>> = Vec::new();
    for zone in file.local_zones.resolve {
        let zone: Name<'static> = zone
            .parse()
            .with_context(|| format!("stage `{name}`: `local_zones.resolve`: `{zone}`"))?;
        ensure!(
            !resolved.contains(&zone),
            "stage `{name}`: `local_zones.resolve`: `{zone}` is listed twice"
        );
        resolved.push(zone.clone());
        stage = stage
            .resolving(&zone)
            .with_context(|| format!("stage `{name}`: `local_zones.resolve`"))?;
    }
    Ok(Stage::Recurse(stage))
}

/// The root hints of the file at `path`, which hold an address that is asked unless `local` (D191): with none every
/// query would fail, and SERVFAIL would be the only sign.
fn read_hints(path: &Path, local: bool) -> anyhow::Result<RootHints> {
    let text = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let roots = RootHints::read(&text).with_context(|| path.display().to_string())?;
    ensure!(
        local
            || (roots.servers().iter())
                .flat_map(Server::addresses)
                .any(askable),
        "{} holds no address that is asked (loopback, private and the other special-purpose ranges are not unless \
         `query_local_addresses` is set)",
        path.display()
    );
    Ok(roots)
}

/// The limits of `file`, the default's where unset.
fn limits(file: LimitsFile) -> anyhow::Result<Limits> {
    let default = Limits::default();
    let or = |set: Option<NonZeroUsize>, default, (name, max): (&str, usize)| {
        let value = set.map_or(default, NonZeroUsize::get);
        ensure!(value <= max, "`limits.{name}` is above {max}");
        Ok::<_, anyhow::Error>(value)
    };
    let time = match file.time_ms {
        Some(ms) => {
            let time = Duration::from_millis(ms.get().into());
            ensure!(
                time <= MAX.time,
                "`limits.time_ms` is above {}",
                MAX.time.as_millis()
            );
            time
        }
        None => default.time,
    };
    Ok(Limits {
        queries: or(file.queries, default.queries, ("queries", MAX.queries))?,
        restarts: or(file.restarts, default.restarts, ("restarts", MAX.restarts))?,
        referrals: or(
            file.referrals,
            default.referrals,
            ("referrals", MAX.referrals),
        )?,
        depth: or(file.depth, default.depth, ("depth", MAX.depth))?,
        servers: or(file.servers, default.servers, ("servers", MAX.servers))?,
        targets: or(file.targets, default.targets, ("targets", MAX.targets))?,
        validation: or(
            file.validation,
            default.validation,
            ("validation", MAX.validation),
        )?,
        time,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dedens_resolver::Minimisation;
    use dedens_server::{Pipeline, Stage};

    use super::super::tests::{env, error, read};

    const RECURSIVE: &str = "listen: [\'127.0.0.1:53\']\npipeline: [cache, root]\nstages:\n  cache:\n    type: cache\n    max_ttl: 3600\n  root:\n    type: recurse\n";

    /// The caches of the recurse stage of `pipeline`, after its cache stage.
    fn caches(pipeline: &Pipeline) -> &Arc<dedens_resolver::Caches> {
        let [Stage::Cache(_), Stage::Recurse(recurse)] = pipeline.stages() else {
            panic!("a cache stage, then a recurse stage")
        };
        recurse.caches()
    }

    use caches as caches_of;

    #[test]
    fn d195_a_recurse_stage_reads_under_the_cache_stages_ttls() {
        let config = read(RECURSIVE, env, &Pipeline::default()).expect("valid");
        let caches = caches(&config.pipeline);
        assert_eq!(caches.rrsets.config().max_ttl, 3600);
        assert_eq!(caches.rrsets.capacity(), dedens_resolver::DEFAULT_CAPACITY);
        assert_eq!(
            caches.infra.capacity(),
            dedens_resolver::InfraCache::DEFAULT_CAPACITY
        );
    }

    #[test]
    fn d195_a_reload_keeps_the_caches_while_their_settings_stay() {
        let first = read(RECURSIVE, env, &Pipeline::default()).expect("valid");
        let limited = format!(
            "{RECURSIVE}    limits: {{queries: 10}}\n    local_zones: {{resolve: [home.arpa]}}\n"
        );
        let same = read(&limited, env, &first.pipeline).expect("valid");
        assert!(Arc::ptr_eq(caches(&first.pipeline), caches(&same.pipeline)));
        // The client share too, its budget the same, not when it changes.
        let share = |pipeline: &Pipeline| {
            let [_, Stage::Recurse(recurse)] = pipeline.stages() else {
                panic!("a cache stage, then a recurse stage")
            };
            Arc::clone(recurse.share().expect("a share"))
        };
        assert!(Arc::ptr_eq(&share(&first.pipeline), &share(&same.pipeline)));
        let other = format!("{RECURSIVE}    client_share: {{burst: 10}}\n");
        let other = read(&other, env, &first.pipeline).expect("valid");
        assert!(!Arc::ptr_eq(
            &share(&first.pipeline),
            &share(&other.pipeline)
        ));
        for changed in [
            RECURSIVE.replace("3600", "7200"),
            format!("{RECURSIVE}    rrset_cache_bytes: 16777216\n"),
            format!("{RECURSIVE}    infra_cache_bytes: 1048576\n"),
        ] {
            let other = read(&changed, env, &first.pipeline).expect("valid");
            assert!(
                !Arc::ptr_eq(caches(&first.pipeline), caches(&other.pipeline)),
                "{changed}"
            );
        }
    }

    /// A reload serving other zones locally flushes the cache stage before the recurse stage, which holds the answers
    /// the zones resolved to, or were served locally with.
    #[test]
    fn d195_a_reload_serving_other_zones_locally_flushes_the_cache_stage() {
        let cache = |pipeline: &Pipeline| match pipeline.stages().first() {
            Some(Stage::Cache(cache)) => Arc::clone(cache),
            stage => unreachable!("{stage:?}"),
        };
        let first = read(RECURSIVE, env, &Pipeline::default()).expect("valid");
        let same = read(RECURSIVE, env, &first.pipeline).expect("valid");
        assert!(Arc::ptr_eq(&cache(&first.pipeline), &cache(&same.pipeline)));
        let resolving = format!("{RECURSIVE}    local_zones: {{resolve: [home.arpa]}}\n");
        let other = read(&resolving, env, &same.pipeline).expect("valid");
        assert!(!Arc::ptr_eq(
            &cache(&same.pipeline),
            &cache(&other.pipeline)
        ));
    }

    /// The recurse example of the module docs reads, and sets the defaults it says.
    #[test]
    fn d195_the_documented_example_reads() {
        let docs = include_str!("mod.rs");
        let example = (docs.split("//! ```yaml\n").nth(2))
            .and_then(|block| block.split("//! ```").next())
            .expect("a second example")
            .lines()
            .map(|line| {
                line.trim_start_matches("//!")
                    .strip_prefix(' ')
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let config = read(&example, env, &Pipeline::default()).expect("the example reads");
        let [Stage::Cache(_), Stage::Recurse(recurse)] = config.pipeline.stages() else {
            panic!("a cache stage, then a recurse stage")
        };
        let defaults = read(RECURSIVE, env, &Pipeline::default()).expect("valid");
        let [_, Stage::Recurse(default)] = defaults.pipeline.stages() else {
            panic!("a cache stage, then a recurse stage")
        };
        assert_eq!(
            recurse.caches().rrsets.capacity(),
            default.caches().rrsets.capacity()
        );
        assert_eq!(
            recurse.caches().infra.capacity(),
            default.caches().infra.capacity()
        );
        assert_eq!(recurse.limits(), default.limits());
        assert_eq!(recurse.minimisation(), default.minimisation());
        assert_eq!(recurse.minimisation(), Minimisation::Relaxed);
    }

    /// D201: `root_hints` replaces the bundled root hints and the TLD hints; a reload with the same file keeps the
    /// caches, one with another file or none does not; a file that is not hints is refused.
    #[test]
    fn d201_root_hints_replace_the_bundled_ones() {
        let path = std::env::temp_dir().join(format!("dedensd-hints-{}", std::process::id()));
        std::fs::write(
            &path,
            ". 3600000 IN NS a.root.\na.root. 3600000 IN A 127.0.0.2\n",
        )
        .unwrap();
        let text = format!(
            "{RECURSIVE}    root_hints: {}\n    query_local_addresses: true\n",
            path.display()
        );
        let bundled = read(RECURSIVE, env, &Pipeline::default()).expect("valid");
        let private = read(&text, env, &bundled.pipeline).expect("valid");
        let caches = caches(&private.pipeline);
        let [server] = caches.roots.servers() else {
            panic!("the one root server of the file")
        };
        assert_eq!(server.name().to_string(), "a.root.");
        assert_eq!(server.ipv4(), [core::net::Ipv4Addr::new(127, 0, 0, 2)]);
        assert!(caches.tlds.is_none(), "no TLD hints with a private root");
        assert!(caches_of(&bundled.pipeline).tlds.is_some());
        assert!(!Arc::ptr_eq(caches, caches_of(&bundled.pipeline)));
        let same = read(&text, env, &private.pipeline).expect("valid");
        assert!(Arc::ptr_eq(caches, caches_of(&same.pipeline)));
        std::fs::write(
            &path,
            ". 3600000 IN NS b.root.\nb.root. 3600000 IN A 127.0.0.3\n",
        )
        .unwrap();
        let other = read(&text, env, &private.pipeline).expect("valid");
        assert!(
            !Arc::ptr_eq(caches, caches_of(&other.pipeline)),
            "hints changed"
        );
        std::fs::write(&path, ". 3600000 IN NS c.root.\n").unwrap();
        let message = error(&text);
        assert!(message.contains("`root_hints`"), "{message}");
        std::fs::remove_file(&path).unwrap();
        let message = error(&text);
        assert!(message.contains("cannot read"), "{message}");
    }

    /// D191: root hints none of whose addresses is asked would answer every question SERVFAIL, silently: refused at
    /// load unless `query_local_addresses` is on, or another address is asked.
    #[test]
    fn d191_root_hints_at_addresses_not_asked_are_refused() {
        let path = std::env::temp_dir().join(format!("dedensd-local-{}", std::process::id()));
        let local = ". 3600000 IN NS a.root.\na.root. 3600000 IN A 127.0.0.2\n";
        std::fs::write(&path, local).unwrap();
        let text = format!("{RECURSIVE}    root_hints: {}\n", path.display());
        let message = error(&text);
        assert!(message.contains("`root_hints`"), "{message}");
        assert!(message.contains("`query_local_addresses`"), "{message}");
        read(
            &format!("{text}    query_local_addresses: true\n"),
            env,
            &Pipeline::default(),
        )
        .expect("asked when set");
        // One server at an address asked is enough.
        let mixed = format!("{local}. 3600000 IN NS b.root.\nb.root. 3600000 IN A 192.0.2.1\n");
        std::fs::write(&path, mixed).unwrap();
        read(&text, env, &Pipeline::default()).expect("one address asked");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn d191_query_local_addresses_reads_off_by_default() {
        for (written, set) in [("", false), ("    query_local_addresses: true\n", true)] {
            let config = format!("{RECURSIVE}{written}");
            let config = read(&config, env, &Pipeline::default()).expect("valid");
            let [_, Stage::Recurse(recurse)] = config.pipeline.stages() else {
                panic!("a cache stage, then a recurse stage")
            };
            assert_eq!(recurse.local_addresses(), set, "{written}");
        }
    }

    #[test]
    fn d199_aggressive_nsec_reads_on_by_default() {
        for (written, set) in [
            ("", true),
            ("    aggressive_nsec: true\n", true),
            ("    aggressive_nsec: false\n", false),
        ] {
            let config = format!("{RECURSIVE}{written}");
            let config = read(&config, env, &Pipeline::default()).expect("valid");
            let [_, Stage::Recurse(recurse)] = config.pipeline.stages() else {
                panic!("a cache stage, then a recurse stage")
            };
            assert_eq!(recurse.aggressive(), set, "{written}");
        }
    }

    #[test]
    fn d198_qname_minimisation_reads() {
        for (written, minimisation) in [
            ("relaxed", Minimisation::Relaxed),
            ("strict", Minimisation::Strict),
            ("none", Minimisation::Off),
        ] {
            let config = format!("{RECURSIVE}    qname_minimisation: {written}\n");
            let config = read(&config, env, &Pipeline::default()).expect("valid");
            let [_, Stage::Recurse(recurse)] = config.pipeline.stages() else {
                panic!("a cache stage, then a recurse stage")
            };
            assert_eq!(recurse.minimisation(), minimisation, "{written}");
        }
        let message = error(&format!("{RECURSIVE}    qname_minimisation: lax\n"));
        assert!(message.contains("lax"), "{message}");
    }

    /// D197: a recurse stage validates when told, as a forward stage; a reload validating the same way keeps its
    /// caches and its validator, one validating otherwise flushes them and the cache stage, whose answers were
    /// judged by the old one.
    #[test]
    fn d197_a_recurse_stage_validates_by_default_and_a_reload_changing_it_flushes_the_caches() {
        fn recurse(pipeline: &Pipeline) -> (Arc<dedens_cache::Cache>, &dedens_server::Recurse) {
            match pipeline.stages() {
                [Stage::Cache(cache), Stage::Recurse(recurse)] => (Arc::clone(cache), recurse),
                stages => unreachable!("{stages:?}"),
            }
        }
        let off = read(
            &format!("{RECURSIVE}    dnssec: off\n"),
            env,
            &Pipeline::default(),
        )
        .expect("valid")
        .pipeline;
        assert!(recurse(&off).1.validation().is_none());
        // Unwritten, it validates (D197); written, the same.
        let text = RECURSIVE;
        let validate = read(text, env, &off).expect("valid").pipeline;
        let (cache, stage) = recurse(&validate);
        assert!(stage.validation().is_some());
        assert!(!Arc::ptr_eq(&recurse(&off).0, &cache), "off to validate");
        let written = format!("{RECURSIVE}    dnssec: validate\n");
        let written = read(&written, env, &validate).expect("valid").pipeline;
        assert!(Arc::ptr_eq(&recurse(&written).0, &cache), "the default");
        assert!(Arc::ptr_eq(recurse(&written).1.caches(), stage.caches()));
        assert!(!Arc::ptr_eq(recurse(&off).1.caches(), stage.caches()));
        let same = read(text, env, &validate).expect("valid").pipeline;
        assert!(Arc::ptr_eq(&recurse(&same).0, &cache), "unchanged");
        assert!(Arc::ptr_eq(recurse(&same).1.caches(), stage.caches()));
        assert_eq!(recurse(&same).1.validation_tag(), stage.validation_tag());
        let validator =
            |stage: &dedens_server::Recurse| stage.validation().unwrap().validator().clone();
        assert!(
            validator(recurse(&same).1).shares_cache(&validator(stage)),
            "the keys proven kept"
        );
        let insecure = format!("{text}    insecure: [corp.example]\n");
        let insecure = read(&insecure, env, &same).expect("valid").pipeline;
        assert!(
            !Arc::ptr_eq(&recurse(&insecure).0, &cache),
            "negative anchor added"
        );
        assert!(!Arc::ptr_eq(recurse(&insecure).1.caches(), stage.caches()));
        assert!(
            error(&format!(
                "{RECURSIVE}    dnssec: off\n    insecure: [corp.example]\n"
            ))
            .contains("need `dnssec: validate`")
        );
    }

    #[test]
    fn d195_a_pipeline_forwards_or_recurses_not_both() {
        let both = "listen: [\'127.0.0.1:53\']\npipeline: [root, up]\nstages:\n  root:\n    type: recurse\n  up:\n    type: forward\n    servers: [\'192.0.2.1\']\n";
        assert_eq!(
            error(both),
            "stages `up` and `root`: a pipeline forwards or recurses, not both"
        );
        let after = "listen: [\'127.0.0.1:53\']\npipeline: [root, c]\nstages:\n  c:\n    type: cache\n  root:\n    type: recurse\n";
        assert_eq!(
            error(after),
            "stage `c` comes after a recurse stage, which answers every query"
        );
    }

    #[test]
    fn d195_settings_out_of_bounds_are_refused() {
        for (setting, expected) in [
            (
                "limits: {time_ms: 30001}",
                "stage `root`: `limits.time_ms` is above 30000",
            ),
            ("limits: {queries: 201}", "`limits.queries` is above 200"),
            ("limits: {restarts: 256}", "`limits.restarts` is above 255"),
            (
                "limits: {referrals: 131}",
                "`limits.referrals` is above 130",
            ),
            ("limits: {depth: 8}", "`limits.depth` is above 7"),
            ("limits: {servers: 101}", "`limits.servers` is above 100"),
            ("limits: {targets: 17}", "`limits.targets` is above 16"),
            (
                "limits: {validation: 201}",
                "`limits.validation` is above 200",
            ),
            ("limits: {queries: 0}", "nonzero"),
            ("limits: {speed: 1}", "speed"),
            (
                "local_zones: {resolve: [example.com]}",
                "example.com. is not a locally served zone",
            ),
            (
                "local_zones: {resolve: [\'a..b\']}",
                "`local_zones.resolve`: `a..b`",
            ),
            (
                "local_zones: {resolve: [home.arpa, home.arpa.]}",
                "`local_zones.resolve`: `home.arpa.` is listed twice",
            ),
            ("client_share: {burst: 2000000000}", "client_share"),
            ("rrset_cache_bytes: 1", "rrset_cache_bytes"),
            ("infra_cache_bytes: 1", "infra_cache_bytes"),
            ("prewarm: {}", "prewarm"),
        ] {
            let message = error(&format!("{RECURSIVE}    {setting}\n"));
            assert!(message.contains(expected), "{setting}: {message}");
        }
        let most = "limits: {queries: 200, restarts: 255, referrals: 130, depth: 7, servers: 100, targets: 16, \
                    validation: 200, time_ms: 30000}";
        read(
            &format!("{RECURSIVE}    {most}\n"),
            env,
            &Pipeline::default(),
        )
        .expect("the most reads");
        let warm = RECURSIVE.replace("max_ttl: 3600", "prewarm: {entries: [example.com]}");
        assert!(error(&warm).contains("`prewarm` has no forward stage"));
    }
}
