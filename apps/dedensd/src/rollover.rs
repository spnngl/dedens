//! The root's trust anchors followed through a key rollover by RFC 5011 (D200), for the validating recurse stages
//! without `trust_anchors`. A serving thread asks the root's DNSKEY `RRset` through the recurse stage when it is due
//! ([`Probe`]); the thread reloading follows it with a [`Rollover`] ([`Kept::observe`]), keeps its state in
//! `state_dir` ([`STATE`]), written whole (D104), and reloads once the anchors it trusts change. The state read at
//! start serves before the anchors of D128, downloaded or bundled, which are warned of when they disagree; with no
//! state those anchors serve and seed a new state at the next answer. A state that does not read is set aside as
//! [`BAD`], warned of, and those anchors serve the same way; one the system fails to read stays where it is, and nothing is
//! seeded or written until it reads. A revoked key is never trusted again (RFC 5011 §2.1):
//! the state keeps it, alone when every key trusted was revoked, and it is taken out of the anchors of D128 that
//! serve then, or seed a new state; a state whose keys sign the root's no more, where those anchors do, is replaced
//! by them, its revoked keys kept.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, mpsc};

use dedens_dnssec::{Rollover, TrustAnchors};
use dedens_proto::Record;

use crate::config::unix_seconds;
use crate::download;
use crate::roots::{open, read_capped};
use crate::sync::{AtomicU64, Ordering};

/// The state of the rollover followed, in `state_dir`.
pub(crate) const STATE: &str = "root-5011";

/// What a state that does not read is set aside as, in `state_dir`, for the operator to read, `BAD.<Unix seconds>`
/// (`.<n>` more within the same second): its revoked keys are lost to the new state, and an earlier one set aside is
/// the evidence of what went wrong first, so none is overwritten.
pub(crate) const BAD: &str = "root-5011.bad";

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

    /// The hand to ask the root's keys with when they are due at `now`: this caller, alone, asks them and hands
    /// the answer to [`Taken::answered`]. Dropping it unanswered, a panic or a cancelled task, hands an empty
    /// answer, a failure asked again after [`RETRY`]: the keys are never left unasked until a restart.
    pub(crate) fn take(&self, now: u64) -> Option<Taken<'_>> {
        let due = self.due.load(Ordering::Acquire);
        let taken = now >= due
            && (self.due)
                .compare_exchange(due, NEVER, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        taken.then(|| Taken {
            probe: self,
            answer: Vec::new(),
        })
    }

    /// Hands `answer`, the root's DNSKEY `RRset` and its signatures, to the thread reloading.
    fn send(&self, answer: Vec<Record<'static>>) {
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

/// The right to ask the root's keys that [`Probe::take`] gave, which hands an answer to the thread reloading when
/// dropped: the one of [`Taken::answered`], else an empty one.
#[derive(Debug)]
pub(crate) struct Taken<'a> {
    probe: &'a Probe,
    answer: Vec<Record<'static>>,
}

impl Taken<'_> {
    /// Hands `answer`, the root's DNSKEY `RRset` and its signatures, to the thread reloading.
    pub(crate) fn answered(mut self, answer: Vec<Record<'static>>) {
        self.answer = answer;
    }
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        self.probe.send(std::mem::take(&mut self.answer));
    }
}

/// The rollover followed, held across reloads by the thread reloading: read from `state_dir` the first time it is
/// needed, seeded by the anchors of D128 when there is none.
#[derive(Debug, Default)]
pub(crate) struct Kept {
    state: State,
    /// The anchors served and those of D128 the last warning was about, until they agree again: the same pair is
    /// not warned of at each reload.
    told: Option<(TrustAnchors, TrustAnchors)>,
}

/// What [`Kept`] read.
#[derive(Debug, Default)]
enum State {
    /// Not read yet, or not readable (no fault of the file's content): the next use reads it again.
    #[default]
    Unread,
    Read(Option<Rollover>),
}

/// What the file of the state held.
enum Stored {
    /// No file.
    Absent,
    Found(Rollover),
    /// Not read for a cause that is no fault of its content (EACCES, EIO, a lack of memory or descriptors): it may
    /// hold a good state with its tombstones, so it is left where it is.
    Unreadable,
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
    /// Reads the rollover kept in `state_dir` unless it is read; whether it is. Not when the file cannot be read
    /// for no fault of its content, which is warned of: it stays where it is, and the next call reads it again.
    fn load(&mut self, state_dir: &Path) -> bool {
        if matches!(self.state, State::Unread) {
            self.state = match read(state_dir) {
                Stored::Absent => State::Read(None),
                Stored::Found(rollover) => State::Read(Some(rollover)),
                Stored::Unreadable => return false,
            };
        }
        true
    }

    /// The rollover kept, once [`Kept::load`]ed; `None` when there is none, or it did not read, which was warned of
    /// and set aside: the anchors of D128 seed a new one.
    fn rollover(&mut self) -> Option<&mut Rollover> {
        match &mut self.state {
            State::Read(rollover) => rollover.as_mut(),
            State::Unread => None,
        }
    }

    /// Whether `pair`, what [`Kept::anchors`] serves and what it differs from, is new since the last one told, the
    /// first of a run of the same: warned of, then only debugged. `None`, they agree, ends the run.
    fn is_news(&mut self, pair: Option<(TrustAnchors, TrustAnchors)>) -> bool {
        let news = pair.is_some() && self.told != pair;
        self.told = pair;
        news
    }

    /// The root anchors the validators trust, `seed` those of D128: the rollover's, warned of when they disagree
    /// with `seed`; when it holds revoked keys only, `seed` less those; else `seed`.
    pub(crate) fn anchors(&mut self, state_dir: &Path, seed: &TrustAnchors) -> TrustAnchors {
        if !self.load(state_dir) {
            return seed.clone();
        }
        let Some(rollover) = self.rollover() else {
            return seed.clone();
        };
        let Some(anchors) = rollover.anchors() else {
            let served = rollover.without_revoked(seed);
            let message = "every root key followed by RFC 5011 is revoked: trusting the downloaded or bundled \
                           anchors, less the revoked keys";
            if self.is_news(Some((served.clone(), seed.clone()))) {
                tracing::warn!(message);
            } else {
                tracing::debug!(message);
            }
            return served;
        };
        let agrees = rollover.agrees(seed);
        let news = self.is_news((!agrees).then(|| (anchors.clone(), seed.clone())));
        let message = "the root keys followed by RFC 5011 are not those of the downloaded or bundled anchors: \
                       trusting those followed";
        if news {
            tracing::warn!(message);
        } else if !agrees {
            tracing::debug!(message);
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
        // A state that cannot be read is neither seeded over nor written: its tombstones would be lost.
        if !self.load(state_dir) {
            metrics::counter!(PROBES, "outcome" => "failed").increment(1);
            tracing::warn!(
                "the root's keys not followed, the state cannot be read: asked again in an hour"
            );
            return Observed {
                wait: RETRY,
                changed: false,
            };
        }
        let was_full = self.rollover().is_some_and(|rollover| rollover.is_full());
        let before =
            (self.rollover()).map(|rollover| (rollover.to_string(), served(rollover, seed)));
        let followed = match self.rollover() {
            // A state that missed a whole rollover, offline past it, is replaced by the download that did not, its
            // revoked keys kept.
            Some(rollover) => rollover.observe(records, now).or_else(|error| {
                let (seeded, wait) = rollover.reseed(seed, records, now).map_err(|_| error)?;
                tracing::warn!(
                    "the root keys followed by RFC 5011 sign the root's keys no more, the downloaded or bundled \
                     anchors do: following those"
                );
                *rollover = seeded;
                Ok(wait)
            }),
            None => Rollover::seed(seed, records, now).map(|(rollover, wait)| {
                self.state = State::Read(Some(rollover));
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
        let Some(rollover) = self.rollover() else {
            return Observed {
                wait,
                changed: false,
            };
        };
        let (text, after) = (rollover.to_string(), served(rollover, seed));
        let changed = match &before {
            Some((_, before)) => *before != after,
            None => !rollover.agrees(seed),
        };
        // Once, when the bound is reached: not at every answer after it.
        if rollover.is_full() && !was_full {
            tracing::warn!(
                max = Rollover::MAX_KEYS,
                "the root keys followed by RFC 5011 are at the most: a new key is not followed"
            );
        }
        let path = state_dir.join(STATE);
        if before.is_none_or(|(before, _)| before != text) {
            // What the next start would refuse to read, and replace with a state that forgot the revoked keys.
            if text.len() > Rollover::MAX_LEN {
                tracing::warn!(
                    len = text.len(),
                    max = Rollover::MAX_LEN,
                    "the state of the root keys followed is too long to be read again: not saved"
                );
            } else if let Err(error) = download::replace(&path, text) {
                tracing::warn!(path = %path.display(), %error, "the state of the root keys followed not saved");
            }
        }
        if changed {
            tracing::info!("the root keys followed by RFC 5011 changed, reloading");
        }
        Observed { wait, changed }
    }
}

/// The anchors the validators trust: those of `rollover`, or `seed` less its revoked keys when it holds no other.
fn served(rollover: &Rollover, seed: &TrustAnchors) -> TrustAnchors {
    rollover
        .anchors()
        .unwrap_or_else(|| rollover.without_revoked(seed))
}

/// Renames `path`, in `state_dir`, to the first of [`BAD`]`.<now>` and `.<now>.<n>` that is free, and flushes the
/// directory so that the rename survives a crash; where it went and how that went.
fn set_aside(state_dir: &Path, path: &Path) -> (PathBuf, io::Result<()>) {
    let now = unix_seconds();
    let bad = (0..=u32::MAX)
        .map(|n| match n {
            0 => state_dir.join(format!("{BAD}.{now}")),
            n => state_dir.join(format!("{BAD}.{now}.{n}")),
        })
        .find(|bad| {
            bad.symlink_metadata()
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        })
        .unwrap_or_else(|| state_dir.join(BAD));
    let renamed = std::fs::rename(path, &bad).and_then(|()| download::sync_dir(state_dir));
    (bad, renamed)
}

/// Why the file of the state did not read.
enum Fault {
    /// What is in the file is at fault: a text that is not a state, too long, not UTF-8, or no regular file. It is
    /// the same at the next read.
    Content(anyhow::Error),
    /// The system is at fault (EACCES, EIO, a lack of memory or descriptors): the file may be a good state.
    System(io::Error),
}

impl Fault {
    /// `error` of opening or reading the file: its content when `roots::open` and `roots::read_capped` refuse it
    /// (`InvalidData`, a symbolic link), the system else.
    fn of(error: io::Error) -> Self {
        // `O_NOFOLLOW` refuses a symbolic link with ELOOP, which `io::ErrorKind` names only on nightly.
        #[cfg(unix)]
        let link = error.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32);
        #[cfg(not(unix))]
        let link = false;
        if link || error.kind() == io::ErrorKind::InvalidData {
            Self::Content(error.into())
        } else {
            Self::System(error)
        }
    }
}

/// The rollover kept in `state_dir`. A file whose content does not read is set aside as [`BAD`] and warned of, not
/// left for the next state to overwrite with its revoked keys forgotten; one the system fails to read is left where
/// it is ([`Stored::Unreadable`]).
fn read(state_dir: &Path) -> Stored {
    let path = state_dir.join(STATE);
    let max = u64::try_from(Rollover::MAX_LEN).unwrap_or(u64::MAX);
    let read = || -> Result<Option<Rollover>, Fault> {
        let Some((file, _)) = open(&path).map_err(Fault::of)? else {
            return Ok(None);
        };
        let bytes = read_capped(file, max).map_err(Fault::of)?;
        let text = String::from_utf8(bytes).map_err(|error| Fault::Content(error.into()))?;
        Rollover::read(&text)
            .map(Some)
            .map_err(|error| Fault::Content(error.into()))
    };
    match read() {
        Ok(None) => Stored::Absent,
        Ok(Some(rollover)) => Stored::Found(rollover),
        Err(Fault::Content(error)) => {
            let (bad, set_aside) = set_aside(state_dir, &path);
            tracing::warn!(
                path = %path.display(),
                error = format!("{error:#}"),
                bad = %bad.display(),
                set_aside = ?set_aside,
                "the state of the root keys followed does not read: trusting the downloaded or bundled anchors"
            );
            Stored::Absent
        }
        Err(Fault::System(error)) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "the state of the root keys followed cannot be read: left where it is, the downloaded or bundled \
                 anchors serve, asked again at the next use"
            );
            Stored::Unreadable
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::pin::pin;
    use std::task::{Context, Waker};

    use dedens_proto::{ZoneEntry, ZoneReader};
    use metrics_util::debugging::DebugValue;

    use super::*;

    /// The root's DS record of KSK-2010, as IANA's `root-anchors.xml` lists it.
    pub(crate) const DS_2010: &str =
        ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5\n";
    /// The root's DS record of KSK-2017, as IANA's `root-anchors.xml` lists it.
    const DS_2017: &str =
        ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n";
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

    /// What was set aside in `dir`: each `root-5011.bad.*`'s content, a directory's as empty, sorted.
    fn set_aside(dir: &Path) -> Vec<Vec<u8>> {
        let mut aside: Vec<_> = (fs::read_dir(dir).unwrap().flatten())
            .map(|entry| entry.path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name.starts_with(BAD) && name.len() > BAD.len()
            })
            .map(|path| fs::read(path).unwrap_or_default())
            .collect();
        aside.sort();
        aside
    }

    /// D200: a state cut short or corrupted, or not a file, is set aside as `root-5011.bad.<time>`, each one kept
    /// beside those before it, and left for the downloaded anchors, never trusting nothing; one that is not there
    /// is no state, and sets nothing aside. The next answer seeds a new state.
    #[test]
    fn a_state_that_does_not_read_starts_from_the_downloaded_anchors() {
        let state = tempfile::tempdir().unwrap();
        let (dir, seed) = (state.path(), seed());
        let whole = format!("dedens rfc5011 1\nvalid {}\nend\n", ksk_2010());
        let broken = [
            &whole[..whole.len() - 4],
            "dedens rfc5011 1\nend\n",
            "\u{0}\u{ff}",
        ];
        for broken in broken {
            fs::write(dir.join(STATE), broken).unwrap();
            assert_eq!(Kept::default().anchors(dir, &seed), seed, "{broken:?}");
            assert!(!dir.join(STATE).exists(), "{broken:?}");
        }
        // Within the same second or not, the earlier evidence is not overwritten.
        let mut expected: Vec<_> = broken.iter().map(|text| text.as_bytes().to_vec()).collect();
        expected.sort();
        assert_eq!(set_aside(dir), expected);
        // Not a file: no more readable, set aside as well.
        fs::create_dir(dir.join(STATE)).unwrap();
        assert_eq!(Kept::default().anchors(dir, &seed), seed);
        assert!(!dir.join(STATE).exists());
        assert_eq!(set_aside(dir).len(), 4);

        let mut kept = Kept::default();
        let seeded = kept.observe(&snapshot("20170716113230"), &seed, dir, JULY_2017);
        assert!(!seeded.changed);
        assert_ne!(Kept::default().anchors(dir, &seed), seed);
        assert_eq!(
            set_aside(dir).len(),
            4,
            "a state that reads sets nothing aside"
        );
    }

    /// D200, RFC 5011 §2.1: a state that cannot be read, for a cause that is no fault of its content (here, a
    /// mode of 0 on a file a run as root left), is not set aside: the tombstones in it are not lost to a seed. The
    /// downloaded anchors serve; an answer fails, to be asked again in an hour, without seeding or writing; the
    /// next use reads the file again.
    #[test]
    fn a_state_that_cannot_be_read_is_kept_not_seeded_over() {
        use std::os::unix::fs::PermissionsExt as _;

        if nix::unistd::geteuid().is_root() {
            // Root reads any file.
            return;
        }
        let state = tempfile::tempdir().unwrap();
        let (dir, seed) = (state.path(), seed());
        let path = dir.join(STATE);
        let whole = format!("dedens rfc5011 1\nvalid {}\nend\n", ksk_2010());
        fs::write(&path, &whole).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        let mut kept = Kept::default();
        assert_eq!(kept.anchors(dir, &seed), seed);
        let answer = snapshot("20170716113230");
        let failed = kept.observe(&answer, &seed, dir, JULY_2017);
        assert_eq!(
            failed,
            Observed {
                wait: RETRY,
                changed: false
            }
        );
        assert!(path.exists() && set_aside(dir).is_empty());
        assert_eq!(fs::read_dir(dir).unwrap().count(), 1, "nothing written");

        // Readable again: the next answer follows the state that was kept, not a seed.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), whole);
        let followed = kept.observe(&answer, &seed, dir, JULY_2017);
        assert_eq!(followed.wait, 86_400);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\naddpend "), "{text}");
    }

    /// Whether `anchors` trust KSK-2010, by its DS or as a DNSKEY.
    fn trusts_2010(anchors: &TrustAnchors) -> bool {
        let text = anchors.to_string();
        text.contains("19036") || text.contains("AwEAAagAIKlVZrpC6Ia7")
    }

    /// D200: a disagreement of the anchors followed with those of D128 is warned of once, at each change of
    /// either, not at each reload, which the next answers repeat.
    #[test]
    fn a_disagreement_is_warned_of_once_per_change() {
        let (a, b) = (seed(), TrustAnchors::read(DS_2017).unwrap());
        let mut kept = Kept::default();
        assert!(!kept.is_news(None), "they agree");
        assert!(kept.is_news(Some((a.clone(), b.clone()))));
        assert!(
            !kept.is_news(Some((a.clone(), b.clone()))),
            "the same again"
        );
        assert!(kept.is_news(Some((b.clone(), a.clone()))), "another pair");
        assert!(kept.is_news(Some((a.clone(), b.clone()))));
        assert!(!kept.is_news(None));
        assert!(kept.is_news(Some((a, b))), "they agreed in between");
    }

    /// D200, RFC 5011 §2.1: a state whose every trusted key is revoked is kept, the revoked key its tombstone: the
    /// downloaded anchors serve less that key, whatever form they hold it in, across restarts and a reseed, which
    /// the stale download that still lists it cannot undo.
    #[test]
    fn a_revoked_key_is_never_trusted_again() {
        let state = tempfile::tempdir().unwrap();
        let (dir, seed) = (state.path(), seed());
        fs::write(
            dir.join(STATE),
            format!("dedens rfc5011 1\nvalid {}\nend\n", ksk_2010()),
        )
        .unwrap();
        let mut kept = Kept::default();
        assert!(trusts_2010(&kept.anchors(dir, &seed)));
        let revoked = kept.observe(&snapshot("20190305003355"), &seed, dir, MARCH_2019);
        assert_eq!(
            revoked,
            Observed {
                wait: 60 * 60,
                changed: true
            }
        );
        let text = fs::read_to_string(dir.join(STATE)).unwrap();
        assert!(text.contains("\nrevoked "), "{text}");
        assert!(!trusts_2010(&kept.anchors(dir, &seed)));
        assert!(
            !trusts_2010(&Kept::default().anchors(dir, &seed)),
            "restarted"
        );

        // The predating download lists KSK-2010 and KSK-2017: the second is trusted, the first no more.
        let predating = TrustAnchors::read(&format!(
            "{DS_2010}. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"
        ))
        .unwrap();
        let april_2019 = 1_554_897_600;
        let mut restarted = Kept::default();
        let reseeded = restarted.observe(&snapshot("20190406221638"), &predating, dir, april_2019);
        assert!(reseeded.changed);
        let served = restarted.anchors(dir, &predating);
        assert!(served.to_string().contains("AwEAAaz/tAm8yTn4Mfeh"));
        assert!(!trusts_2010(&served));
        let text = fs::read_to_string(dir.join(STATE)).unwrap();
        assert!(text.contains("\nrevoked "), "{text}");
        assert!(
            !trusts_2010(&Kept::default().anchors(dir, &predating)),
            "restarted"
        );
    }

    /// D200: a state longer than `Rollover::MAX_LEN` is not written, as the next start would refuse to read it: the
    /// file stays as it was; one of exactly that length is.
    #[test]
    fn a_state_too_long_to_be_read_again_is_not_saved() {
        // KSK-2010 and two filler keys (invented bytes: only their length matters) that bring the text to the limit
        // once KSK-2010 is revoked ("revoked <time>" is longer than "valid"). The first filler's length moves it by
        // 4, the algorithm numbers of the two by a digit each: a text of any length is reached.
        let march = snapshot("20190305003355");
        let whole = |filler: usize, algorithms: (u8, u8)| {
            format!(
                "dedens rfc5011 1\nvalid {}\nvalid 257 3 {} {}\nvalid 257 3 {} AAAA\nend\n",
                ksk_2010(),
                algorithms.0,
                "A".repeat(filler),
                algorithms.1
            )
        };
        let revoked = |text: &str| {
            let mut rollover = Rollover::read(text).ok()?;
            // No trusted key signs the rest: only the revocation moves the state.
            rollover.observe(&march, MARCH_2019).unwrap_err();
            Some(rollover.to_string().len())
        };
        let reaching = |len: usize| {
            let mut candidates = [(9, 10), (9, 100), (10, 100), (100, 200)]
                .into_iter()
                .flat_map(|algorithms| {
                    (len / 4 * 4 - 1000..len)
                        .step_by(4)
                        .map(move |filler| whole(filler, algorithms))
                });
            candidates
                .find(|text| revoked(text) == Some(len))
                .expect("a text of that length")
        };
        for (len, saved) in [(Rollover::MAX_LEN, true), (Rollover::MAX_LEN + 1, false)] {
            let state = tempfile::tempdir().unwrap();
            let dir = state.path();
            let text = reaching(len);
            fs::write(dir.join(STATE), &text).unwrap();
            let observed = Kept::default().observe(&march, &seed(), dir, MARCH_2019);
            assert!(observed.changed, "served, saved or not: {len}");
            let kept = fs::read_to_string(dir.join(STATE)).unwrap();
            assert_eq!(kept == text, !saved, "{len}");
            assert_eq!(kept.len() == len, saved, "{len}");
            assert_eq!(set_aside(dir), Vec::<Vec<u8>>::new());
        }
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
        assert!(probe.take(0).is_none(), "no stage follows them");
        probe.start(10);
        assert!(probe.take(9).is_none());
        assert!(probe.take(10).is_some());
        assert!(probe.take(11).is_none(), "taken");
        probe.wait(11, 5);
        assert!(probe.take(15).is_none());
        assert!(probe.take(16).is_some());
        probe.stop();
        assert!(probe.take(NEVER - 1).is_none());
        let (reload, wakes) = mpsc::channel();
        probe.connect(reload);
        probe.start(0);
        let taken = probe.take(0).expect("due");
        taken.answered(snapshot("20170716113230"));
        assert!(matches!(wakes.try_recv(), Ok(Wake::RootKeys(answer)) if !answer.is_empty()));
        assert!(wakes.try_recv().is_err(), "answered once");
    }

    /// D200: a task that took the root's keys and was dropped or panicked before answering hands an empty answer,
    /// which the thread reloading asks again after an hour, rather than leaving them unasked until a restart.
    #[test]
    fn the_root_keys_taken_and_never_answered_fail_and_are_asked_again() {
        let (probe, (reload, wakes)) = (Probe::default(), mpsc::channel());
        probe.connect(reload);
        probe.start(0);
        {
            let mut asking = pin!(async {
                let _taken = probe.take(0).expect("due");
                std::future::pending::<()>().await;
            });
            let mut cx = Context::from_waker(Waker::noop());
            assert!(asking.as_mut().poll(&mut cx).is_pending());
            assert!(wakes.try_recv().is_err(), "still asking");
        }
        assert!(matches!(wakes.try_recv(), Ok(Wake::RootKeys(answer)) if answer.is_empty()));

        let panicked = std::panic::catch_unwind(|| {
            probe.start(0);
            let _taken = probe.take(0).expect("due");
            panic!("the keys future");
        });
        assert!(panicked.is_err());
        assert!(matches!(wakes.try_recv(), Ok(Wake::RootKeys(answer)) if answer.is_empty()));
    }
}
