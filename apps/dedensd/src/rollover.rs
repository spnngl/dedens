//! The root's trust anchors followed through a key rollover by RFC 5011 (D200), for the validating recurse stages
//! without `trust_anchors`. A serving thread asks the root's DNSKEY `RRset` through the recurse stage when it is due
//! ([`Probe`]); the thread reloading follows it with a [`Rollover`] ([`Kept::observe`]), keeps its state in
//! `state_dir` ([`STATE`]), written whole (D104), and reloads once the anchors it trusts change. The state read at
//! start serves before the anchors of D128, downloaded or bundled, which are warned of when they disagree; with no
//! state, or one that does not read, which is warned of, those anchors serve and seed a new state at the next
//! answer. A state that comes to trust no key, every one revoked, is dropped the same way: a validator never trusts
//! nothing; one whose keys sign the root's no more, where those anchors do, is replaced by them.

use std::path::Path;
use std::sync::{OnceLock, mpsc};

use dedens_dnssec::{Rollover, TrustAnchors};
use dedens_proto::Record;

use crate::download;
use crate::roots::{open, read_capped};
use crate::sync::{AtomicU64, Ordering};

/// The state of the rollover followed, in `state_dir`.
pub(crate) const STATE: &str = "root-5011";

/// The root's keys asked, by `outcome`: `followed` (the answer verified, the state moved on) or `failed` (no
/// answer, or none a trusted key signs; asked again after [`RETRY`]).
const PROBES: &str = "dedensd_root_key_probes_total";

/// The wait after a query that failed, an hour: the floor of RFC 5011 §2.3's `retryTime`, which needs the TTL and
/// signatures a failed query did not bring. Unbound (`validator/autotrust.c`, `set_tp_times`) and BIND
/// (`lib/dns/zone.c`, `refresh_time`) compute it, between an hour and a day: about 5 hours for the root.
pub(crate) const RETRY: u64 = 60 * 60;

/// Describes the metrics of this module.
pub(crate) fn describe() {
    metrics::describe_counter!(
        PROBES,
        "Queries of the root's DNSKEY RRset to follow its trust anchors by RFC 5011, by outcome: followed (the \
         answer verified) or failed (asked again in an hour) (D200)."
    );
}

/// What wakes the thread reloading.
#[derive(Debug)]
pub(crate) enum Wake {
    /// A SIGHUP: the configuration file is read again (D55).
    Hangup,
    /// The answer to the root's keys asked by a serving thread, with its signatures; empty when it failed.
    RootKeys(Vec<Record<'static>>),
}

/// When the root's keys are next asked, shared by the serving threads and set by the thread reloading, which the
/// answer goes to.
#[derive(Debug)]
pub(crate) struct Probe {
    /// Unix seconds; [`NEVER`] while no stage follows the root's keys, or once a thread took it to ask them.
    due: AtomicU64,
    /// The thread reloading, once started.
    reload: OnceLock<mpsc::Sender<Wake>>,
}

/// Not due.
const NEVER: u64 = u64::MAX;

impl Default for Probe {
    fn default() -> Self {
        Self {
            due: AtomicU64::new(NEVER),
            reload: OnceLock::new(),
        }
    }
}

impl Probe {
    /// Connects it to the thread reloading.
    pub(crate) fn connect(&self, reload: mpsc::Sender<Wake>) {
        let _ = self.reload.set(reload);
    }

    /// Whether the root's keys are due at `now`: then this caller, alone, asks them and hands the answer to
    /// [`Probe::answered`].
    pub(crate) fn take(&self, now: u64) -> bool {
        let due = self.due.load(Ordering::Acquire);
        now >= due
            && (self.due)
                .compare_exchange(due, NEVER, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    /// Hands `answer`, the root's DNSKEY `RRset` and its signatures, to the thread reloading.
    pub(crate) fn answered(&self, answer: Vec<Record<'static>>) {
        if let Some(reload) = self.reload.get() {
            let _ = reload.send(Wake::RootKeys(answer));
        }
    }

    /// Asks the root's keys at once: a stage starts following them.
    pub(crate) fn start(&self, now: u64) {
        self.due.store(now, Ordering::Release);
    }

    /// Asks the root's keys at `now` plus `wait` seconds.
    pub(crate) fn wait(&self, now: u64, wait: u64) {
        self.due.store(now.saturating_add(wait), Ordering::Release);
    }

    /// Asks them no more: no stage follows them.
    pub(crate) fn stop(&self) {
        self.due.store(NEVER, Ordering::Release);
    }
}

/// The rollover followed, held across reloads by the thread reloading: read from `state_dir` the first time it is
/// needed, seeded by the anchors of D128 when there is none.
#[derive(Debug, Default)]
pub(crate) enum Kept {
    #[default]
    Unread,
    Read(Option<Rollover>),
}

/// What an answer changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observed {
    /// Seconds until the root's keys are asked again (RFC 5011 §2.3).
    pub(crate) wait: u64,
    /// Whether the anchors the validators trust changed: the configuration is loaded again.
    pub(crate) changed: bool,
}

impl Kept {
    /// The rollover kept in `state_dir`, read the first time; `None` when there is none, or it does not read,
    /// which is warned of: the anchors of D128 seed a new one.
    fn rollover(&mut self, state_dir: &Path) -> Option<&mut Rollover> {
        if matches!(self, Self::Unread) {
            *self = Self::Read(read(&state_dir.join(STATE)));
        }
        match self {
            Self::Read(rollover) => rollover.as_mut(),
            Self::Unread => None,
        }
    }

    /// The root anchors the validators trust, `seed` those of D128: the rollover's, warned of when they disagree
    /// with `seed`, else `seed`.
    pub(crate) fn anchors(&mut self, state_dir: &Path, seed: &TrustAnchors) -> TrustAnchors {
        let followed = (self.rollover(state_dir))
            .and_then(|rollover| Some((rollover.anchors()?, rollover.agrees(seed))));
        let Some((anchors, agrees)) = followed else {
            return seed.clone();
        };
        if !agrees {
            tracing::warn!(
                "the root keys followed by RFC 5011 are not those of the downloaded or bundled anchors: trusting \
                 those followed"
            );
        }
        anchors
    }

    /// Follows the rollover with `records`, the root's keys answered at `now`, seeded by `seed` when none is kept,
    /// and saves it in `state_dir` when it moved on.
    pub(crate) fn observe(
        &mut self,
        records: &[Record<'_>],
        seed: &TrustAnchors,
        state_dir: &Path,
        now: u64,
    ) -> Observed {
        let before =
            (self.rollover(state_dir)).map(|rollover| (rollover.to_string(), rollover.anchors()));
        let followed = match self.rollover(state_dir) {
            // A state that missed a whole rollover, offline past it, is replaced by the download that did not.
            Some(rollover) => rollover.observe(records, now).or_else(|error| {
                let (seeded, wait) = Rollover::seed(seed, records, now).map_err(|_| error)?;
                tracing::warn!(
                    "the root keys followed by RFC 5011 sign the root's keys no more, the downloaded or bundled \
                     anchors do: following those"
                );
                *rollover = seeded;
                Ok(wait)
            }),
            None => Rollover::seed(seed, records, now).map(|(rollover, wait)| {
                *self = Self::Read(Some(rollover));
                wait
            }),
        };
        let wait = match followed {
            Ok(wait) => {
                metrics::counter!(PROBES, "outcome" => "followed").increment(1);
                tracing::debug!(wait, "root keys followed");
                wait
            }
            Err(error) => {
                metrics::counter!(PROBES, "outcome" => "failed").increment(1);
                tracing::warn!(%error, "the root's keys not followed, asked again in an hour");
                RETRY
            }
        };
        // A revocation counts even when no trusted key signs the rest (RFC 5011 §2.1).
        let Some(rollover) = self.rollover(state_dir) else {
            return Observed {
                wait,
                changed: false,
            };
        };
        let (text, after) = (rollover.to_string(), rollover.anchors());
        let changed = match &before {
            Some((_, before)) => *before != after,
            None => !rollover.agrees(seed),
        };
        let path = state_dir.join(STATE);
        if after.is_none() {
            tracing::warn!(
                "no root key followed by RFC 5011 is trusted any more: trusting the downloaded or bundled anchors"
            );
            *self = Self::Read(None);
            remove(&path);
        } else if before.is_none_or(|(before, _)| before != text)
            && let Err(error) = download::replace(&path, text)
        {
            tracing::warn!(path = %path.display(), %error, "the state of the root keys followed not saved");
        }
        if changed {
            tracing::info!("the root keys followed by RFC 5011 changed, reloading");
        }
        Observed { wait, changed }
    }
}

/// The rollover kept at `path`; `None` when there is none, or it does not read, which is warned of.
fn read(path: &Path) -> Option<Rollover> {
    let max = u64::try_from(Rollover::MAX_LEN).unwrap_or(u64::MAX);
    let read = open(path).map_err(anyhow::Error::from).and_then(|opened| {
        let Some((file, _)) = opened else {
            return Ok(None);
        };
        let text = String::from_utf8(read_capped(file, max)?)?;
        Ok(Some(Rollover::read(&text)?))
    });
    match read {
        Ok(rollover) => rollover,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = format!("{error:#}"),
                "the state of the root keys followed does not read: trusting the downloaded or bundled anchors"
            );
            None
        }
    }
}

/// Removes the state at `path`, which trusts no key.
fn remove(path: &Path) {
    if let Err(error) = std::fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), %error, "the state of the root keys followed not removed");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;

    use dedens_proto::{ZoneEntry, ZoneReader};
    use metrics_util::debugging::DebugValue;

    use super::*;

    /// The root's DS record of KSK-2010, as IANA's `root-anchors.xml` lists it.
    pub(crate) const DS_2010: &str =
        ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5\n";
    /// 2017-07-16 12:00 UTC: KSK-2017 published.
    pub(crate) const JULY_2017: u64 = 1_500_206_400;
    /// 2017-08-16 12:00 UTC: a day after its add hold-down ends.
    pub(crate) const AUGUST_2017: u64 = 1_502_884_800;
    /// 2019-03-05 12:00 UTC: KSK-2010 revoked.
    const MARCH_2019: u64 = 1_551_787_200;

    /// The root's DNSKEY `RRset` and its signatures, as `just capture-rollover` captured it at `at`.
    pub(crate) fn snapshot(at: &str) -> Vec<Record<'static>> {
        let text = fs::read_to_string(dedens_testkit::path(&format!("dnssec/rollover-{at}.zone")))
            .unwrap();
        ZoneReader::new(text.as_bytes(), None)
            .filter_map(|entry| match entry.unwrap() {
                ZoneEntry::Record(decoded) => Some(decoded.record),
                _ => None,
            })
            .collect()
    }

    /// The text of the root's KSK-2010, unrevoked, as in a state.
    fn ksk_2010() -> String {
        let text = fs::read_to_string(dedens_testkit::path("dnssec/rollover-20181224040024.zone"))
            .unwrap();
        let line = text
            .lines()
            .find(|line| line.contains("257 3 8 AwEAAagAIKlVZrpC6Ia7"))
            .unwrap();
        line.split_once("DNSKEY\t").unwrap().1.to_owned()
    }

    pub(crate) fn seed() -> TrustAnchors {
        TrustAnchors::read(DS_2010).unwrap()
    }

    /// D200: the downloaded anchors seed the state at the first answer, saved in `state_dir` and read at the next
    /// start; a key past its add hold-down reloads the configuration, an answer no trusted key signs changes
    /// nothing and is asked again in an hour.
    #[test]
    fn the_downloaded_anchors_seed_a_state_kept_across_restarts() {
        let state = tempfile::tempdir().unwrap();
        let (dir, seed) = (state.path(), seed());
        let mut kept = Kept::default();
        assert_eq!(kept.anchors(dir, &seed), seed);
        let day = 86_400;
        let seeded = kept.observe(&snapshot("20170716113230"), &seed, dir, JULY_2017);
        assert_eq!(
            seeded,
            Observed {
                wait: day,
                changed: false
            }
        );
        let started = Kept::default().anchors(dir, &seed);
        assert_ne!(started, seed, "DNSKEY anchors, of the same key");
        assert!(
            started.to_string().contains("257 3 8 AwEAAagAIKlVZrpC6Ia7"),
            "{started}"
        );

        let trusted = kept.observe(&snapshot("20170816120412"), &seed, dir, AUGUST_2017);
        assert_eq!(
            trusted,
            Observed {
                wait: day,
                changed: true
            }
        );
        let restarted = Kept::default().anchors(dir, &seed);
        assert_eq!(restarted, kept.anchors(dir, &seed));
        assert_ne!(restarted, started);

        let text = fs::read_to_string(dir.join(STATE)).unwrap();
        let unsigned = kept.observe(&[], &seed, dir, AUGUST_2017);
        assert_eq!(
            unsigned,
            Observed {
                wait: 60 * 60,
                changed: false
            }
        );
        assert_eq!(fs::read_to_string(dir.join(STATE)).unwrap(), text);
    }

    /// D200: a state that missed a whole rollover, KSK-2010 alone trusted when only KSK-2017 signs, is replaced by
    /// the downloaded anchors when they sign the answer, and kept when they do not either.
    #[test]
    fn a_state_past_a_whole_rollover_follows_the_download() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let downloaded = TrustAnchors::read(
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
        )
        .unwrap();
        let april_2019 = 1_554_897_600;
        let kept = format!("dedens rfc5011 1\nvalid {}\nend\n", ksk_2010());
        fs::write(dir.join(STATE), &kept).unwrap();
        let mut stale = Kept::default();
        let answer = snapshot("20190406221638");
        let failed = stale.observe(&answer, &seed(), dir, april_2019);
        assert_eq!(
            failed,
            Observed {
                wait: 60 * 60,
                changed: false
            }
        );
        assert_eq!(fs::read_to_string(dir.join(STATE)).unwrap(), kept);

        let followed = stale.observe(&answer, &downloaded, dir, april_2019);
        assert_eq!(
            followed,
            Observed {
                wait: 86_400,
                changed: true
            }
        );
        assert!(
            Kept::default()
                .anchors(dir, &seed())
                .to_string()
                .contains("AwEAAaz/tAm8yTn4Mfeh")
        );
    }

    /// D200: a state cut short or corrupted is left for the downloaded anchors, never trusting nothing, and replaced
    /// at the next answer.
    #[test]
    fn a_state_that_does_not_read_starts_from_the_downloaded_anchors() {
        let state = tempfile::tempdir().unwrap();
        let (dir, seed) = (state.path(), seed());
        let whole = format!("dedens rfc5011 1\nvalid {}\nend\n", ksk_2010());
        for broken in [
            &whole[..whole.len() - 4],
            "dedens rfc5011 1\nend\n",
            "\u{0}\u{ff}",
        ] {
            fs::write(dir.join(STATE), broken).unwrap();
            assert_eq!(Kept::default().anchors(dir, &seed), seed, "{broken:?}");
        }
        let mut kept = Kept::default();
        let seeded = kept.observe(&snapshot("20170716113230"), &seed, dir, JULY_2017);
        assert!(!seeded.changed);
        assert_ne!(Kept::default().anchors(dir, &seed), seed);
    }

    /// D200: a state whose every trusted key is revoked is dropped, its file removed: the downloaded anchors serve
    /// again, and seed the next state.
    #[test]
    fn a_state_that_trusts_no_key_is_dropped() {
        let state = tempfile::tempdir().unwrap();
        let (dir, seed) = (state.path(), seed());
        fs::write(
            dir.join(STATE),
            format!("dedens rfc5011 1\nvalid {}\nend\n", ksk_2010()),
        )
        .unwrap();
        let mut kept = Kept::default();
        assert_ne!(kept.anchors(dir, &seed), seed);
        let revoked = kept.observe(&snapshot("20190305003355"), &seed, dir, MARCH_2019);
        assert_eq!(
            revoked,
            Observed {
                wait: 60 * 60,
                changed: true
            }
        );
        assert!(!dir.join(STATE).exists());
        assert_eq!(kept.anchors(dir, &seed), seed);
    }

    /// D200: the metric of the root's keys asked is described, through `describe` that `main` calls, and counts
    /// each answer by outcome.
    #[test]
    fn the_root_keys_asked_are_counted_by_outcome() {
        let state = tempfile::tempdir().unwrap();
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            describe();
            let mut kept = Kept::default();
            kept.observe(
                &snapshot("20170716113230"),
                &seed(),
                state.path(),
                JULY_2017,
            );
            kept.observe(&[], &seed(), state.path(), JULY_2017);
            kept.observe(&[], &seed(), state.path(), JULY_2017);
        });
        let mut counted: Vec<_> = (recorder.snapshotter().snapshot().into_vec().into_iter())
            .map(|(key, _, description, value)| {
                let outcome = key
                    .key()
                    .labels()
                    .map(|label| label.value().to_owned())
                    .collect::<Vec<_>>();
                (
                    key.key().name().to_owned(),
                    outcome,
                    description.is_some(),
                    value,
                )
            })
            .collect();
        counted.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            counted,
            [
                (
                    PROBES.to_owned(),
                    vec!["failed".to_owned()],
                    true,
                    DebugValue::Counter(2)
                ),
                (
                    PROBES.to_owned(),
                    vec!["followed".to_owned()],
                    true,
                    DebugValue::Counter(1)
                ),
            ]
        );
    }

    /// D200: the root's keys are asked by one thread once due, the answer handed to the thread reloading.
    #[test]
    fn the_root_keys_are_asked_once_when_due() {
        let probe = Probe::default();
        assert!(!probe.take(0), "no stage follows them");
        probe.start(10);
        assert!(!probe.take(9));
        assert!(probe.take(10));
        assert!(!probe.take(11), "taken");
        probe.wait(11, 5);
        assert!(!probe.take(15));
        assert!(probe.take(16));
        probe.stop();
        assert!(!probe.take(NEVER - 1));
        let (reload, wakes) = mpsc::channel();
        probe.connect(reload);
        probe.answered(Vec::new());
        assert!(matches!(wakes.try_recv(), Ok(Wake::RootKeys(answer)) if answer.is_empty()));
    }
}
