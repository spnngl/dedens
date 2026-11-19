//! A `recurse` stage, as written and built (D195): the resolution's limits (D191), the zones served locally to
//! resolve instead (RFC 6303 §3), a client network's share of the queries (D117), and the sizes of its caches (D193,
//! D194). A reload keeps its caches while their sizes and the cache stage's settings stay, and the share's buckets
//! while its budget stays.

use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use dedens_proto::Name;
use dedens_resolver::{Caches, DEFAULT_CAPACITY, InfraCache, Limits, RrsetCache};
use dedens_roots::{RootHints, Tlds};
use dedens_server::{Budgets, DEFAULT_SHARE, Pipeline, Recurse, Stage};
use serde::Deserialize;

use super::limits::BudgetFile;

/// A `recurse` stage's settings.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecurseFile {
    #[serde(default)]
    limits: LimitsFile,
    #[serde(default)]
    local_zones: LocalZonesFile,
    client_share: Option<BudgetFile>,
    rrset_cache_bytes: Option<NonZeroUsize>,
    infra_cache_bytes: Option<NonZeroUsize>,
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
    time_ms: Option<NonZeroU32>,
}

/// The most each count of `limits` may be set to, the highest BIND or Unbound allows or uses, so that no setting
/// lets one client question cost what neither would (D195).
const MAX: Limits = Limits {
    // BIND's `max-query-count` 200: the queries of a client question, validation's included.
    queries: 200,
    // BIND's `max-query-restarts` range, 1 to 255.
    restarts: 255,
    // Unbound's `MAX_REFERRAL_COUNT` 130 (`iterator/iterator.h`).
    referrals: 130,
    // BIND's `max-recursion-depth` 7.
    depth: 7,
    // BIND's `max-delegation-servers` range, 1 to 100.
    servers: 100,
    // Unbound's `MAX_DP_TARGET_COUNT` 16 (`iterator/iterator.h`).
    targets: 16,
    // A client gives up well before, and a resolution holds one of the thread's upstream queries (D47) all along.
    time: Duration::from_secs(30),
};

/// The zones served locally, all of them unless listed in `resolve`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalZonesFile {
    #[serde(default)]
    resolve: Vec<String>,
}

/// The stage `name` of `file`, after the stages `built`: its TTLs bounded as their cache stage's, if any; its caches
/// those of `previous`'s recurse stage when their sizes and settings are the same.
///
/// # Errors
///
/// A limit above [`MAX`]'s; a zone in `local_zones.resolve` that is not a name, not served locally or listed twice; a
/// `client_share` [`Budgets::new`] refuses; caches [`RrsetCache::new`] or [`InfraCache::new`] refuses.
pub(super) fn recurse(
    name: &str,
    file: RecurseFile,
    built: &[Stage],
    previous: &Pipeline,
) -> anyhow::Result<Stage> {
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
    let kept = previous.stages().iter().find_map(|stage| match stage {
        Stage::Recurse(held) => {
            let caches = held.caches();
            let same = caches.rrsets.capacity() == rrset_bytes
                && caches.infra.capacity() == infra_bytes
                && caches.rrsets.config() == cache;
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
            roots: RootHints::bundled().clone(),
            tlds: Some(Tlds::bundled().clone()),
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
    let mut stage = Recurse::new(caches).with_limits(limits).with_share(share);
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
        time,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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
                    time_ms: 30000}";
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
