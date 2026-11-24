//! The secondary zones of the `authoritative` stage (D215): each transferred from its primaries, refreshed, retried
//! and expired by the timers of its SOA (RFC 1034 §4.3.5), kept across restarts in `state_dir/zones/` ([`disk`]).
//!
//! One thread, `dedensd-secondaries`, owns them all: their files, their timers and their transfers, run together on
//! its runtime, at most [`IN_FLIGHT`] at once. It learns the zones from the thread reloading, after each
//! configuration built ([`Secondaries::configure`]), and gives it back each new version, or the end of one at its
//! expire ([`Wake::Zone`]): that thread builds the pipeline again, which serves it. A zone without a version is
//! answered SERVFAIL (`Authoritative::with_unavailable`). The task is generic over [`Io`], so that the simulator
//! drives its clock (D182).
//!
//! A refresh asks each primary in order for its SOA, then transfers from the first that answers when its serial is
//! ahead of ours (RFC 1982): IXFR from ours, AXFR without one, `dedens_net::transfer` falling back from one to the
//! other (D210). A primary whose serial is behind ours is not followed: the version stays and its expire runs on,
//! as Knot does (`finalize_timers_noexpire`, `src/knot/events/handlers/refresh.c`). A transfer is checked as a zone
//! file is (D204): its warnings are logged, an error refuses it and the last version stays.

mod disk;
mod timers;

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::ops::RangeFrom;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::{Arc, mpsc};
use std::time::Duration;
use std::{future, thread};

use dedens_net::io::{Compio, Io};
use dedens_net::transfer::{self, Limits, Transfer, TransferError};
use dedens_proto::{Name, Serial};
use dedens_tsig::Key;
use dedens_zone::{Changeset, Loaded, Report, Zone};
use futures_util::FutureExt as _;
use futures_util::future::{Either, select};
use futures_util::stream::{FuturesUnordered, StreamExt as _};

use self::disk::{Disk, Kept};
use self::timers::{Intervals, bootstrap_at};
use crate::rollover::Wake;

/// The most refreshes under way at once, the secondaries' together: 8. A refresh holds a TCP connection and, for an
/// AXFR, the zone it builds, up to [`Limits::default`]'s bounds (D210): this bounds the memory a burst of them takes,
/// at the start of a server with many zones. Knot runs them on its `background-workers`, as many as CPUs; NSD keeps
/// up to `xfrd-tcp-max`, 128, connections open (`options.c`); BIND `transfers-in`, 10.
const IN_FLIGHT: usize = 8;

/// Refreshes by result: `full` or `incremental` (a new version), `uptodate`, `behind` (the primary's serial is
/// behind ours), `refused` (the transfer did not check), or `failed` (no primary answered).
const REFRESHES: &str = "dedensd_authoritative_refreshes_total";
/// Versions dropped at their expire.
const EXPIRED: &str = "dedensd_authoritative_expired_total";

/// Describes the metrics of the secondary zones.
pub(crate) fn describe() {
    metrics::describe_counter!(
        REFRESHES,
        "Refreshes of the secondary zones, by result: full, incremental, uptodate, behind, refused or failed (D215)."
    );
    metrics::describe_counter!(
        EXPIRED,
        "Secondary zones dropped at their SOA expire, answered SERVFAIL until transferred again (D215)."
    );
}

/// A secondary zone, as configured.
#[derive(Debug, Clone)]
pub(crate) struct Secondary {
    pub(crate) apex: Name<'static>,
    /// Asked in order.
    pub(crate) primaries: Vec<Primary>,
}

/// A primary of a secondary zone.
#[derive(Debug, Clone)]
pub(crate) struct Primary {
    pub(crate) address: SocketAddr,
    /// What signs the queries (RFC 8945), if any.
    pub(crate) key: Option<Key>,
}

/// What the secondaries' thread is asked.
#[derive(Debug)]
enum Command {
    /// The secondary zones are now these.
    Configure(Vec<Secondary>),
    /// Refresh this zone now.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "NOTIFY sends it, step 15 of the authoritative phase"
        )
    )]
    Refresh(Name<'static>),
}

/// The secondaries' thread, started with the first secondary zone configured.
#[derive(Debug)]
pub(crate) struct Secondaries {
    /// The directory of the zones' files.
    zones: PathBuf,
    /// Where new versions go.
    wakes: mpsc::Sender<Wake>,
    /// The thread's commands, once started.
    commands: Option<flume::Sender<Command>>,
}

impl Secondaries {
    /// The thread of the secondary zones kept in `state_dir`, giving its versions to `wakes`; not started yet.
    pub(crate) fn new(state_dir: &Path, wakes: mpsc::Sender<Wake>) -> Self {
        Self {
            zones: dir(state_dir),
            wakes,
            commands: None,
        }
    }

    /// The secondary zones are now `secondaries`, of a configuration whose `state_dir` is `state_dir`: those new to
    /// the thread are read from their files, those no longer there dropped. The thread starts with the first; one
    /// that cannot start is logged, and tried again at the next call. Once it runs, the files stay in the
    /// `state_dir` of the start.
    pub(crate) fn configure(&mut self, state_dir: &Path, secondaries: Vec<Secondary>) {
        if self.commands.is_some() && dir(state_dir) != self.zones {
            tracing::warn!("changes to `state_dir` take a restart for the secondary zones");
        }
        if self.commands.is_none() && !secondaries.is_empty() {
            let (commands, received) = flume::unbounded();
            let (zones, wakes) = (self.zones.clone(), self.wakes.clone());
            let started = thread::Builder::new()
                .name("dedensd-secondaries".to_owned())
                .spawn(move || match crate::serve::runtime() {
                    Ok(runtime) => runtime.block_on(run(Compio, zones, received, wakes)),
                    Err(error) => tracing::error!(%error, "secondary zones not served: no runtime"),
                });
            match started {
                Ok(_) => self.commands = Some(commands),
                Err(error) => tracing::error!(%error, "secondary zones not served: no thread"),
            }
        }
        if let Some(commands) = &self.commands {
            let _ = commands.send(Command::Configure(secondaries));
        }
    }

    /// Refreshes the secondary zone of apex `apex` now, as a NOTIFY asks (RFC 1996 §3.11); nothing when it is not
    /// one, or a refresh of it is under way.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "NOTIFY calls it, step 15 of the authoritative phase"
        )
    )]
    pub(crate) fn refresh(&self, apex: Name<'static>) {
        if let Some(commands) = &self.commands {
            let _ = commands.send(Command::Refresh(apex));
        }
    }
}

/// The directory of the secondary zones' files in `state_dir`.
pub(crate) fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("zones")
}

/// A secondary zone, as the thread holds it.
#[derive(Debug)]
struct Held {
    primaries: Vec<Primary>,
    /// The version served and its timers; `None` before the first transfer and after an expire.
    version: Option<(Arc<Zone>, Kept)>,
    disk: Disk,
    /// When it is refreshed next, Unix seconds.
    next: u64,
    /// The tries that failed in a row while it has no version.
    tries: u32,
    /// The number of the refresh under way, if any: the result of another is dropped.
    refreshing: Option<u64>,
}

/// A refresh to start: the zone's apex and primaries, our serial, and the refresh's number.
type Start = (Name<'static>, Vec<Primary>, Option<Serial>, u64);

/// The refreshes of the zones of `held` due at `now` to start, at most `room`, each zone marked under way with the
/// next of `numbers`.
fn start(
    held: &mut BTreeMap<Name<'static>, Held>,
    now: u64,
    room: usize,
    numbers: &mut RangeFrom<u64>,
) -> Vec<Start> {
    let due = (held.iter_mut()).filter(|(_, zone)| zone.refreshing.is_none() && zone.next <= now);
    (due.take(room))
        .map(|(apex, zone)| {
            let number = numbers.next().unwrap_or_default();
            zone.refreshing = Some(number);
            let ours =
                (zone.version.as_ref()).map(|(version, _)| Serial::new(version.soa().serial));
            (apex.clone(), zone.primaries.clone(), ours, number)
        })
        .collect()
}

/// When the task has something to do next, Unix seconds: refresh a zone or expire its version. Refreshes do not
/// count when no more can start, `in_flight` being under way: one ending wakes the task.
fn soonest(held: &BTreeMap<Name<'static>, Held>, in_flight: usize) -> Option<u64> {
    let room = in_flight < IN_FLIGHT;
    let next = |zone: &Held| (room && zone.refreshing.is_none()).then_some(zone.next);
    let expires = |zone: &Held| zone.version.as_ref().map(|(_, kept)| kept.expires);
    (held.values())
        .flat_map(|zone| next(zone).into_iter().chain(expires(zone)))
        .min()
}

/// What wakes the secondaries' task.
#[derive(Debug)]
enum Event {
    /// A command; `None` once the sender dropped.
    Command(Option<Command>),
    Refreshed(Refreshed),
    /// A timer: the top of the loop does what is due.
    Due,
}

/// The result of a refresh.
#[derive(Debug)]
struct Refreshed {
    apex: Name<'static>,
    number: u64,
    outcome: Outcome,
}

/// What a refresh found.
#[derive(Debug)]
enum Outcome {
    /// A new version, from `primary`.
    Transferred {
        transfer: Transfer,
        primary: SocketAddr,
    },
    /// The primary's serial is ours.
    UpToDate,
    /// The primary's serial is behind ours, or 2³¹ away (RFC 1982 §3.2): it is not followed.
    Behind { primary: SocketAddr, serial: Serial },
    /// No primary answered.
    Failed,
}

/// The secondaries' task: the zones of the commands received, their files in `zones`, their versions sent to
/// `wakes`. Ends when the commands' sender drops.
async fn run<N: Io>(
    io: N,
    zones: PathBuf,
    commands: flume::Receiver<Command>,
    wakes: mpsc::Sender<Wake>,
) {
    let mut held = BTreeMap::<Name<'static>, Held>::new();
    let mut refreshing = FuturesUnordered::new();
    let mut numbers = 0_u64..;
    loop {
        let now = io.unix_time();
        expire(&mut held, now, &wakes);
        let room = IN_FLIGHT.saturating_sub(refreshing.len());
        for (apex, primaries, ours, number) in start(&mut held, now, room, &mut numbers) {
            refreshing.push(refresh(&io, apex, primaries, ours, number));
        }
        let soonest = soonest(&held, refreshing.len());
        let event = {
            let command = pin!(commands.recv_async());
            let refreshed = pin!(async {
                match refreshing.next().await {
                    Some(refreshed) => refreshed,
                    None => future::pending().await,
                }
            });
            let either = select(command, refreshed).map(|either| match either {
                Either::Left((command, _)) => Event::Command(command.ok()),
                Either::Right((refreshed, _)) => Event::Refreshed(refreshed),
            });
            let deadline = soonest
                .and_then(|at| (io.now()).checked_add(Duration::from_secs(at.saturating_sub(now))));
            match deadline {
                Some(deadline) => io.timeout_at(deadline, either).await.unwrap_or(Event::Due),
                None => either.await,
            }
        };
        match event {
            Event::Due => {}
            Event::Command(Some(Command::Configure(secondaries))) => {
                held = configure(held, secondaries, &zones, (&io, &wakes));
            }
            Event::Command(Some(Command::Refresh(apex))) => {
                if let Some(zone) = held.get_mut(&apex) {
                    zone.next = zone.next.min(io.unix_time());
                }
            }
            Event::Command(None) => return,
            Event::Refreshed(refreshed) => {
                let Some(zone) = (held.get_mut(&refreshed.apex))
                    .filter(|zone| zone.refreshing == Some(refreshed.number))
                else {
                    continue;
                };
                zone.refreshing = None;
                let (now, draw) = (io.unix_time(), draw(&io));
                if let Some(version) =
                    refreshed_zone(&refreshed.apex, zone, refreshed.outcome, (now, draw))
                {
                    let _ = wakes.send(Wake::Zone(refreshed.apex, Some(version)));
                }
            }
        }
    }
}

/// `held` with the zones of `secondaries`: each kept, with its primaries now; new ones read from their files in
/// `zones`, a version found sent to `wakes`; the others dropped, their refresh under way with them.
fn configure<N: Io>(
    mut held: BTreeMap<Name<'static>, Held>,
    secondaries: Vec<Secondary>,
    zones: &Path,
    (io, wakes): (&N, &mpsc::Sender<Wake>),
) -> BTreeMap<Name<'static>, Held> {
    secondaries
        .into_iter()
        .map(|Secondary { apex, primaries }| {
            let zone = if let Some(zone) = held.remove(&apex) {
                Held { primaries, ..zone }
            } else {
                let zone = adopt(&apex, primaries, zones, (io.unix_time(), draw(io)));
                if let Some((version, _)) = &zone.version {
                    let _ = wakes.send(Wake::Zone(apex.clone(), Some(Arc::clone(version))));
                }
                zone
            };
            (apex, zone)
        })
        .collect()
}

/// The zone of `apex`, new to the thread, with the version kept in its files below `zones`, unless expired at
/// `now`; refreshed when its SOA says, at once without a version.
fn adopt(
    apex: &Name<'static>,
    primaries: Vec<Primary>,
    zones: &Path,
    (now, draw): (u64, u64),
) -> Held {
    let mut disk = Disk::new(disk::dir_of(zones, apex));
    let version = match disk.load(apex) {
        Ok(Some((zone, kept))) if kept.expires > now => {
            tracing::info!(zone = %apex, serial = zone.soa().serial, records = zone.record_count(), "secondary zone read from disk");
            Some((Arc::new(zone), kept))
        }
        Ok(Some(_)) => {
            tracing::warn!(zone = %apex, "secondary zone on disk expired, transferring it again");
            None
        }
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(zone = %apex, error = format!("{error:#}"), "secondary zone on disk not read, transferring it again");
            None
        }
    };
    let next = version.as_ref().map_or(now, |(zone, kept)| {
        Intervals::of(zone.soa()).refresh_at(kept.refreshed, draw)
    });
    Held {
        primaries,
        version,
        disk,
        next,
        tries: 0,
        refreshing: None,
    }
}

/// Drops the versions of `held` expired at `now` (RFC 1034 §4.3.5), each sent to `wakes` as `None`.
fn expire(held: &mut BTreeMap<Name<'static>, Held>, now: u64, wakes: &mpsc::Sender<Wake>) {
    for (apex, zone) in held {
        if zone
            .version
            .as_ref()
            .is_some_and(|(_, kept)| kept.expires <= now)
        {
            zone.version = None;
            metrics::counter!(EXPIRED).increment(1);
            tracing::error!(zone = %apex, "secondary zone expired, answered SERVFAIL until transferred again");
            let _ = wakes.send(Wake::Zone(apex.clone(), None));
        }
    }
}

/// Refreshes `apex`, at `ours` or without a version, from the first of `primaries` that answers.
async fn refresh<N: Io>(
    io: &N,
    apex: Name<'static>,
    primaries: Vec<Primary>,
    ours: Option<Serial>,
    number: u64,
) -> Refreshed {
    let limits = Limits::default();
    let mut outcome = Outcome::Failed;
    for Primary { address, key } in &primaries {
        let tried = async {
            let soa = transfer::soa(io, *address, &apex, key.as_ref()).await?;
            let theirs = Serial::new(soa.serial);
            match ours.map(|ours| theirs.partial_cmp(&ours)) {
                Some(Some(Ordering::Equal)) => return Ok(Outcome::UpToDate),
                Some(Some(Ordering::Less) | None) => {
                    return Ok(Outcome::Behind {
                        primary: *address,
                        serial: theirs,
                    });
                }
                Some(Some(Ordering::Greater)) | None => {}
            }
            let transfer =
                transfer::transfer(io, *address, &apex, ours, key.as_ref(), &limits).await?;
            Ok::<_, TransferError>(Outcome::Transferred {
                transfer,
                primary: *address,
            })
        };
        match tried.await {
            Ok(found) => {
                outcome = found;
                break;
            }
            Err(error) => {
                let error = format!("{:#}", anyhow::Error::new(error));
                tracing::warn!(zone = %apex, primary = %address, error, "secondary zone refresh failed");
            }
        }
    }
    Refreshed {
        apex,
        number,
        outcome,
    }
}

/// A random number from `io`, for a timer's jitter; 0 without one, which only takes the jitter away.
fn draw<N: Io>(io: &N) -> u64 {
    let mut bytes = [0; 8];
    io.random(&mut bytes)
        .map_or(0, |()| u64::from_ne_bytes(bytes))
}

/// The version `transfer` makes of `current`, `apex`'s version if any, from `primary`, with the changesets that make
/// it when incremental; `Err` when it is refused, logged.
fn transferred(
    apex: &Name<'static>,
    current: Option<&Zone>,
    transfer: Transfer,
    primary: SocketAddr,
) -> Result<(Zone, Option<Vec<Changeset>>), ()> {
    let warned = |report: &Report| {
        if !report.warnings.is_empty() {
            tracing::warn!(zone = %apex, %primary, %report, "secondary zone transferred with warnings");
        }
    };
    let (zone, changesets) = match (transfer, current) {
        (Transfer::Full(loaded), _) => {
            warned(&loaded.report);
            (loaded.zone, None)
        }
        (Transfer::Incremental(changesets), Some(current)) => {
            let mut zone = None::<Zone>;
            for changeset in &changesets {
                let from = zone.as_ref().unwrap_or(current);
                match from.apply(changeset, &dedens_zone::Limits::default()) {
                    Ok(Loaded { zone: next, report }) => {
                        warned(&report);
                        zone = Some(next);
                    }
                    Err(report) => {
                        tracing::error!(zone = %apex, %primary, %report, "secondary zone transfer refused, serving the last version");
                        return Err(());
                    }
                }
            }
            (zone.ok_or(())?, Some(changesets))
        }
        // `dedens_net::transfer` answers incremental from a serial only, and up to date only with one: the
        // primary's serial went back between its SOA and its transfer, asked again at the retry.
        (Transfer::Incremental(_), None) | (Transfer::UpToDate, _) => return Err(()),
    };
    let kind = if changesets.is_some() {
        "incremental"
    } else {
        "full"
    };
    tracing::info!(zone = %apex, %primary, serial = zone.soa().serial, records = zone.record_count(), kind, "secondary zone transferred");
    Ok((zone, changesets))
}

/// Takes `outcome`, the end of a refresh of `zone` at `now` (Unix seconds), `draw` a random number for the
/// jitter: the version transferred, kept on disk, and when the zone is refreshed next. A primary that answered
/// sets the refresh, a failure the retry, both from the SOA of the version (RFC 1034 §4.3.5); without a version,
/// tries come sooner ([`bootstrap_at`]). Up to date, the expire starts again; behind, it runs on.
fn refreshed_zone(
    apex: &Name<'static>,
    zone: &mut Held,
    outcome: Outcome,
    (now, draw): (u64, u64),
) -> Option<Arc<Zone>> {
    let (result, answered, new) = match outcome {
        Outcome::Transferred { transfer, primary } => {
            let current = zone.version.as_ref().map(|(version, _)| &**version);
            match transferred(apex, current, transfer, primary) {
                Ok((version, changesets)) => {
                    let version = Arc::new(version);
                    let kept = Kept {
                        refreshed: now,
                        expires: Intervals::of(version.soa()).expire_at(now),
                    };
                    zone.version = Some((Arc::clone(&version), kept));
                    zone.tries = 0;
                    let stored = match &changesets {
                        Some(changesets) => zone.disk.incremental(changesets, &version, kept),
                        None => zone.disk.full(&version, kept),
                    };
                    if let Err(error) = stored {
                        let error = format!("{error:#}");
                        tracing::error!(zone = %apex, error, "secondary zone not kept on disk");
                    }
                    let result = if changesets.is_some() {
                        "incremental"
                    } else {
                        "full"
                    };
                    (result, true, Some(version))
                }
                Err(()) => ("refused", false, None),
            }
        }
        Outcome::UpToDate => {
            if let Some((version, kept)) = &mut zone.version {
                *kept = Kept {
                    refreshed: now,
                    expires: Intervals::of(version.soa()).expire_at(now),
                };
                if let Err(error) = zone.disk.timers(*kept) {
                    let error = format!("{error:#}");
                    tracing::error!(zone = %apex, error, "secondary zone timers not kept on disk");
                }
                tracing::debug!(zone = %apex, serial = version.soa().serial, "secondary zone up to date");
            }
            ("uptodate", true, None)
        }
        Outcome::Behind { primary, serial } => {
            let ours = zone
                .version
                .as_ref()
                .map(|(version, _)| version.soa().serial);
            tracing::warn!(zone = %apex, %primary, serial = serial.get(), ours, "primary serial behind ours, not followed");
            ("behind", true, None)
        }
        Outcome::Failed => ("failed", false, None),
    };
    metrics::counter!(REFRESHES, "result" => result).increment(1);
    zone.next = match &zone.version {
        Some((version, _)) if answered => Intervals::of(version.soa()).refresh_at(now, draw),
        Some((version, _)) => Intervals::of(version.soa()).retry_at(now, draw),
        None => {
            zone.tries = zone.tries.saturating_add(1);
            bootstrap_at(now, zone.tries, draw)
        }
    };
    new
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::Path;
    use std::sync::{Arc, mpsc};

    use dedens_proto::{Name, Serial};

    use super::disk::{Disk, Kept};
    use super::timers::bootstrap_at;
    use super::{BTreeMap, Held, IN_FLIGHT, Outcome, expire, refreshed_zone, soonest, start};
    use crate::rollover::Wake;

    /// The apex of the zone of RFC 4035 Appendix A.
    fn apex() -> Name<'static> {
        "example.".parse().unwrap()
    }

    /// The zone of RFC 4035 Appendix A, its SOA timers 3600 (refresh), 300 (retry) and 3 600 000 (expire), refreshed
    /// at 0, its files in `dir`, a refresh under way.
    fn held(dir: &Path) -> Held {
        let path = dedens_testkit::path("zones/rfc4035_appendix_a.zone");
        let zone = crate::zones::stored(&apex(), &path).unwrap();
        let kept = Kept {
            refreshed: 0,
            expires: 3_600_000,
        };
        Held {
            primaries: Vec::new(),
            version: Some((Arc::new(zone), kept)),
            disk: Disk::new(dir.to_path_buf()),
            next: 3600,
            tries: 0,
            refreshing: Some(0),
        }
    }

    /// The timers of the version of `zone`.
    fn kept(zone: &Held) -> Kept {
        zone.version.as_ref().map(|(_, kept)| *kept).unwrap()
    }

    /// RFC 1034 §4.3.5: a primary that answered sets the refresh, one that did not the retry, each 90 to 100% of
    /// the SOA's (D215); up to date, the expire starts again and is kept on disk; behind, it runs on.
    #[test]
    fn rfc1034_4_3_5_the_soa_times_the_next_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let mut zone = held(dir.path());
        assert!(refreshed_zone(&apex(), &mut zone, Outcome::UpToDate, (10_000, 0)).is_none());
        assert_eq!(zone.next, 10_000 + 3240);
        let renewed = Kept {
            refreshed: 10_000,
            expires: 3_610_000,
        };
        assert_eq!(kept(&zone), renewed);
        let timers = std::fs::read_to_string(dir.path().join("timers")).unwrap();
        assert_eq!(timers, "refreshed 10000\nexpires 3610000\n");

        refreshed_zone(&apex(), &mut zone, Outcome::Failed, (20_000, 0));
        assert_eq!(zone.next, 20_000 + 270);
        assert_eq!(kept(&zone), renewed, "a failure leaves the expire running");

        let primary = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let behind = Outcome::Behind {
            primary,
            serial: Serial::new(1),
        };
        refreshed_zone(&apex(), &mut zone, behind, (30_000, u64::MAX));
        assert_eq!(zone.next, 30_000 + 3240 + u64::MAX % 360);
        assert_eq!(
            kept(&zone),
            renewed,
            "a primary behind leaves the expire running"
        );
    }

    /// Knot `zone_bootstrap_next`: a zone without a version is tried again sooner than its SOA would say, which it
    /// does not have.
    #[test]
    fn a_zone_without_a_version_is_tried_again_sooner() {
        let dir = tempfile::tempdir().unwrap();
        let mut zone = Held {
            version: None,
            ..held(dir.path())
        };
        for tries in 1..=3 {
            refreshed_zone(&apex(), &mut zone, Outcome::Failed, (0, 0));
            assert_eq!(zone.tries, tries);
            assert_eq!(zone.next, bootstrap_at(0, tries, 0));
        }
    }

    /// At most [`IN_FLIGHT`] refreshes are under way; while no more can start, the task sleeps to the next expire,
    /// not to the refreshes waiting, already due.
    #[test]
    fn at_most_in_flight_refreshes_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut zones: BTreeMap<_, _> = (0..=IN_FLIGHT)
            .map(|n| {
                let apex: Name<'static> = format!("z{n}.example.").parse().unwrap();
                let zone = Held {
                    refreshing: None,
                    ..held(dir.path())
                };
                (apex, zone)
            })
            .collect();
        let mut numbers = 0..;
        let started = start(&mut zones, 3600, IN_FLIGHT, &mut numbers);
        assert_eq!(started.len(), IN_FLIGHT);
        assert_eq!(started.last().map(|start| start.3), Some(7));
        let serial = started.first().and_then(|start| start.2);
        assert_eq!(serial.map(Serial::get), Some(1_081_539_377));
        assert_eq!(soonest(&zones, IN_FLIGHT - 1), Some(3600));
        assert_eq!(soonest(&zones, IN_FLIGHT), Some(3_600_000));
        assert_eq!(start(&mut zones, 3600, 1, &mut numbers).len(), 1);
        assert!(start(&mut zones, 3600, 1, &mut numbers).is_empty());
    }

    /// RFC 1034 §4.3.5: a version is dropped at its expire, and the thread reloading told.
    #[test]
    fn rfc1034_4_3_5_a_version_is_dropped_at_its_expire() {
        let dir = tempfile::tempdir().unwrap();
        let mut zones = BTreeMap::from([(apex(), held(dir.path()))]);
        let (wakes, woken) = mpsc::channel();
        expire(&mut zones, 3_599_999, &wakes);
        assert!(woken.try_recv().is_err());
        expire(&mut zones, 3_600_000, &wakes);
        assert!(zones[&apex()].version.is_none());
        assert!(matches!(woken.try_recv(), Ok(Wake::Zone(apex, None)) if apex == self::apex()));
    }

    /// A configuration keeps the zones it names, their versions and timers with its primaries, and drops the others;
    /// a zone kept is not sent again.
    #[test]
    fn a_configuration_keeps_its_zones_with_their_new_primaries() {
        use dedens_net::io::Compio;

        use super::{Primary, Secondary, configure};

        let dir = tempfile::tempdir().unwrap();
        let gone: Name<'static> = "gone.example.".parse().unwrap();
        let zones = BTreeMap::from([(apex(), held(dir.path())), (gone, held(dir.path()))]);
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 5353));
        let secondaries = vec![Secondary {
            apex: apex(),
            primaries: vec![Primary { address, key: None }],
        }];
        let (wakes, woken) = mpsc::channel();
        let zones = configure(zones, secondaries, dir.path(), (&Compio, &wakes));
        assert_eq!(zones.keys().cloned().collect::<Vec<_>>(), [apex()]);
        let zone = &zones[&apex()];
        let primaries: Vec<_> = zone.primaries.iter().map(|p| p.address).collect();
        assert_eq!(primaries, [address]);
        assert_eq!((zone.next, kept(zone).expires), (3600, 3_600_000));
        assert!(woken.try_recv().is_err());
    }

    /// RFC 1034 §4.3.5: a version kept on disk is served up to its expire, not at it; without one, the zone is
    /// refreshed at once.
    #[test]
    fn rfc1034_4_3_5_a_version_on_disk_is_read_before_its_expire() {
        use super::adopt;
        use super::disk::dir_of;

        let dir = tempfile::tempdir().unwrap();
        let zone = held(dir.path()).version.map(|(zone, _)| zone).unwrap();
        let kept = Kept {
            refreshed: 0,
            expires: 3_600_000,
        };
        Disk::new(dir_of(dir.path(), &apex()))
            .full(&zone, kept)
            .unwrap();
        let read = adopt(&apex(), Vec::new(), dir.path(), (3_599_999, 0));
        assert_eq!((read.version.is_some(), read.next), (true, 3240));
        let expired = adopt(&apex(), Vec::new(), dir.path(), (3_600_000, 0));
        assert_eq!(
            (expired.version.is_some(), expired.next),
            (false, 3_600_000)
        );
    }

    /// The jitter is drawn from the I/O's random bytes: two draws are the same once in 2^64.
    #[test]
    fn the_jitter_is_drawn_at_random() {
        use dedens_net::io::Compio;

        assert_ne!(super::draw(&Compio), super::draw(&Compio));
    }

    /// RFC 1996 §3.11: the refresh a NOTIFY asks reaches the thread once it runs, and nothing before.
    #[test]
    fn a_refresh_asked_reaches_the_running_thread() {
        use super::{Command, Secondaries};

        let (wakes, _woken) = mpsc::channel();
        let mut secondaries = Secondaries::new(Path::new("/nonexistent"), wakes);
        secondaries.refresh(apex());
        let (commands, received) = flume::unbounded();
        secondaries.commands = Some(commands);
        secondaries.refresh(apex());
        assert!(matches!(received.try_recv(), Ok(Command::Refresh(asked)) if asked == apex()));
        assert!(received.is_empty());
    }

    /// The counters of the refreshes, by result, and of the expires are described and counted.
    #[test]
    fn refreshes_and_expires_are_counted() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        use super::{EXPIRED, REFRESHES, describe};

        let dir = tempfile::tempdir().unwrap();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let mut zones = BTreeMap::from([(apex(), held(dir.path()))]);
        let (wakes, _woken) = mpsc::channel();
        metrics::with_local_recorder(&recorder, || {
            describe();
            if let Some(zone) = zones.get_mut(&apex()) {
                refreshed_zone(&apex(), zone, Outcome::UpToDate, (0, 0));
                refreshed_zone(&apex(), zone, Outcome::Failed, (0, 0));
            }
            expire(&mut zones, 3_600_000, &wakes);
        });
        let mut counted: Vec<_> = (snapshotter.snapshot().into_vec().into_iter())
            .map(|(key, _, description, value)| {
                let labels: Vec<_> = key.key().labels().map(|l| l.value().to_owned()).collect();
                let count = match value {
                    DebugValue::Counter(count) => count,
                    _ => u64::MAX,
                };
                let name = key.key().name().to_owned();
                (name, labels, description.is_some(), count)
            })
            .collect();
        counted.sort();
        let metric = |name: &str, label: &[&str]| {
            let labels = label.iter().map(|&l| l.to_owned()).collect();
            (name.to_owned(), labels, true, 1)
        };
        assert_eq!(
            counted,
            [
                metric(EXPIRED, &[]),
                metric(REFRESHES, &["failed"]),
                metric(REFRESHES, &["uptodate"]),
            ]
        );
    }
}
