//! An `authoritative` stage, as written and built (D208): the zones it serves, each a name and the file holding it
//! in the presentation format (RFC 1035 §5), kept across reloads while their files stay (D120).

use std::path::PathBuf;

use anyhow::{Context as _, ensure};
use dedens_proto::{Name, Question, RecordType};
use dedens_server::{Authoritative, Stage};
use dedens_zone::End;
use serde::Deserialize;

use crate::lists::Store;

/// The most zones an `authoritative` stage serves: 10 000 (D115). Each is a file read and stamped at every reload
/// (D120), and a line of the configuration; past that, a catalog of zones (RFC 9432) is the tool, which the
/// configuration lacks. Knot, NSD and BIND bound none: NSD serves millions from its `zonelist`, added at run time.
pub(super) const MAX_ZONES: usize = 10_000;

/// An `authoritative` stage's settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthoritativeFile {
    zones: Vec<ZoneFile>,
}

/// A zone, as written: its apex, `name`, and the `file` it is read from; `$INCLUDE` reads files in the directory of
/// `file` or below it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneFile {
    name: Apex,
    file: PathBuf,
}

/// The apex of a zone, in presentation format.
#[derive(Debug, Deserialize)]
#[serde(try_from = "String")]
struct Apex(Name<'static>);

impl TryFrom<String> for Apex {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        text.parse()
            .map(Self)
            .map_err(|error| format!("`{text}` is not a name: {error}"))
    }
}

/// The `authoritative` stage `name` of `file`, its zones from `store`.
///
/// # Errors
///
/// No zone, or more than [`MAX_ZONES`]; a zone given twice; a zone that does not load, at the start or new to the
/// configuration (a zone served keeps its last version, D55).
pub(super) fn authoritative(
    name: &str,
    file: &AuthoritativeFile,
    store: &mut Store,
) -> anyhow::Result<Stage> {
    let count = file.zones.len();
    ensure!(count > 0, "stage `{name}`: `zones` is empty");
    ensure!(
        count <= MAX_ZONES,
        "stage `{name}`: `zones` lists {count} zones, over {MAX_ZONES}"
    );
    let zones = (file.zones.iter())
        .map(|zone| {
            (store.zones.zone(&zone.name.0, &zone.file))
                .with_context(|| format!("stage `{name}`, zone `{}`", zone.name.0))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let stage = Authoritative::new(zones).with_context(|| format!("stage `{name}`"))?;
    warn_undelegated(&stage);
    Ok(Stage::Authoritative(stage))
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

    use dedens_server::Pipeline;

    use super::super::tests::env;
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
