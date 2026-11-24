//! The updates of the zones whose access lists permit them (RFC 2136, D216). A serving thread hands each to the
//! thread reloading ([`Updates::ask`]), which makes them one at a time (§3.7) on the zones it holds
//! ([`Held::update`](crate::zones::Held::update)), saves each new version before the reply (§3.5, [`save`]),
//! serves it, then answers.
//!
//! A zone updated is kept in `state_dir/zones/<zone>/`: `zone`, the version served, written whole after each
//! update, and `journal`, its changesets (D207), the history a transfer by IXFR reads. At a load, the version
//! saved serves unless the zone file's serial is ahead of it ([`restore`]): an operator's edit with a higher
//! serial replaces the updates, as BIND's and Knot's `zonefile-load: difference` do not.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc};

use anyhow::{Context as _, anyhow};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Name, Rcode, Record, Serial, Update};
use dedens_zone::journal::{Journal, JournalError, JournalLimits};
use dedens_zone::{Limits, Source, Updated, Zone};

use crate::rollover::Wake;

/// The most updates waiting for the thread reloading, all zones together: 100, BIND's `update-quota`
/// (`bin/include/defaultconfig.h`), past which it drops them. Knot refuses those past 8 to a zone only while its
/// updates are frozen (`update_process_query`, `src/knot/nameserver/update.c`), and queues the others without
/// bound. One past it is REFUSED with EDE 14, Not Ready (RFC 8914 §4.15), Knot's reply.
pub(crate) const MAX_PENDING: usize = 100;

/// Where the serving threads hand updates: the thread reloading, once started, and the count waiting for it.
#[derive(Debug, Default)]
pub(crate) struct Updates {
    pending: Arc<AtomicUsize>,
    reload: OnceLock<mpsc::Sender<Wake>>,
}

impl Updates {
    /// Connects it to the thread reloading.
    pub(crate) fn connect(&self, reload: mpsc::Sender<Wake>) {
        let _ = self.reload.set(reload);
    }

    /// Hands `update` to the thread reloading: what it made of it comes on the channel returned, the RCODE of the
    /// reply; nothing when the thread panicked. Else the RCODE and EDE of the reply: SERVFAIL with no thread
    /// reloading (§3.4.2.1), REFUSED with EDE 14 past [`MAX_PENDING`].
    pub(crate) fn ask(
        &self,
        update: Update<'static>,
    ) -> Result<flume::Receiver<Rcode>, (Rcode, Option<InfoCode>)> {
        let reload = self.reload.get().ok_or((Rcode::SERVFAIL, None))?;
        self.pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                (pending < MAX_PENDING).then_some(pending + 1)
            })
            .map_err(|_| (Rcode::REFUSED, Some(InfoCode::NOT_READY)))?;
        let (made, answer) = flume::bounded(1);
        let asked = Asked {
            update,
            made,
            pending: Arc::clone(&self.pending),
        };
        reload
            .send(Wake::Update(Box::new(asked)))
            .map_err(|_| (Rcode::SERVFAIL, None))?;
        Ok(answer)
    }
}

/// An UPDATE handed to the thread reloading, counted waiting until dropped.
#[derive(Debug)]
pub(crate) struct Asked {
    pub(crate) update: Update<'static>,
    made: flume::Sender<Rcode>,
    pending: Arc<AtomicUsize>,
}

impl Asked {
    /// Hands `rcode`, what was made of it, to the serving thread, which may have given up.
    pub(crate) fn answer(&self, rcode: Rcode) {
        let _ = self.made.send(rcode);
    }
}

impl Drop for Asked {
    fn drop(&mut self) {
        self.pending.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The directory of the zone of apex `apex` in `state_dir`: `zones/` and its name in lower case, `/` written
/// `\047`; the root's `@`, which a name's text never is alone.
pub(crate) fn dir(state_dir: &Path, apex: &Name<'_>) -> PathBuf {
    let name = if apex.is_root() {
        "@".to_owned()
    } else {
        apex.to_string().to_ascii_lowercase().replace('/', "\\047")
    };
    state_dir.join("zones").join(name)
}

/// The zone the file loaded, `file`, or the version of it saved in `dir` when there is one and the file's serial is
/// not ahead of it (RFC 1982).
pub(crate) fn restore(file: Zone, dir: &Path) -> Zone {
    let apex = file.apex().clone();
    let path = dir.join("zone");
    let saved = match saved(&apex, &path) {
        Ok(Some(saved)) => saved,
        Ok(None) => return file,
        Err(error) => {
            tracing::error!(zone = %apex, file = %path.display(), error = format!("{error:#}"), "updated zone not read, serving the zone file");
            return file;
        }
    };
    let (ours, theirs) = (saved.soa().serial, file.soa().serial);
    if Serial::new(theirs) > Serial::new(ours) {
        tracing::warn!(zone = %apex, serial = theirs, updated = ours, "zone file ahead of the updates: they are dropped");
        return file;
    }
    tracing::info!(zone = %apex, serial = ours, "zone updated before: its last version serves");
    saved
}

/// The zone saved at `path`, `None` when there is none.
fn saved(apex: &Name<'static>, path: &Path) -> anyhow::Result<Option<Zone>> {
    let text = match std::fs::read(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        read => read.with_context(|| format!("reading `{}`", path.display()))?,
    };
    let name = path.display().to_string();
    let source = Source {
        name: &name,
        text: &text,
        default_ttl: None,
    };
    let mut include = |_: &str| Err("not in a zone saved".to_owned());
    let loaded = Zone::load(apex.clone(), source, &mut include, &Limits::default())
        .map_err(|report| anyhow!("{report}"))?;
    Ok(Some(loaded.zone))
}

/// Saves `updated` in `dir`, made if missing: the zone whole first, so that it never falls behind the journal, then
/// its changeset appended to `journal`, opened at the first. A journal whose last serial is not where the
/// changeset starts, after a crash between the two, is cleared first: what it held cannot serve IXFR.
///
/// # Errors
///
/// The directory, the zone or the journal not written: the update is not made.
pub(crate) fn save(
    dir: &Path,
    updated: &Updated,
    journal: &mut Option<Journal>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("making `{}`", dir.display()))?;
    let path = dir.join("zone");
    crate::download::replace(&path, text(&updated.loaded.zone))
        .with_context(|| format!("writing `{}`", path.display()))?;
    let path = dir.join("journal");
    let journal = match journal {
        Some(journal) => journal,
        None => journal.insert(Journal::open(&path, JournalLimits::default())?),
    };
    let appended = match journal.append(&updated.changeset) {
        Err(JournalError::NotConsecutive { .. }) => {
            journal.clear()?;
            journal.append(&updated.changeset)
        }
        appended => appended,
    };
    appended.with_context(|| format!("appending to `{}`", path.display()))?;
    Ok(())
}

/// The text of `zone`: a record a line, its signatures after each node's `RRsets`.
fn text(zone: &Zone) -> String {
    let mut text = String::new();
    for (name, node) in zone.nodes() {
        let sets = node
            .rrsets()
            .map(|(_, set)| set)
            .chain(node.signature_sets());
        for set in sets {
            for rdata in set.rdatas() {
                let record = Record {
                    name: name.clone(),
                    class: zone.class(),
                    ttl: set.ttl(),
                    rdata: rdata.clone(),
                };
                let _ = writeln!(text, "{record}");
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use dedens_proto::{Message, Opcode, Question, RecordType};
    use dedens_testkit::dns;

    use super::*;

    #[test]
    fn a_zone_has_a_directory_of_its_own() {
        let state = Path::new("/state");
        let dir = |apex: &str| dir(state, &dns(apex));
        assert_eq!(dir("Example."), Path::new("/state/zones/example."));
        assert_eq!(dir("."), Path::new("/state/zones/@"));
        assert_eq!(
            dir("a/b.example."),
            Path::new("/state/zones/a\\047b.example.")
        );
    }

    /// An UPDATE of `example.` with no change.
    fn update() -> Update<'static> {
        let mut message = Message::query(1, Question::new(dns("example."), RecordType::SOA));
        message.header.opcode = Opcode::UPDATE;
        Update::read(message).unwrap()
    }

    #[test]
    fn the_updates_waiting_are_bounded() {
        let updates = Updates::default();
        assert_eq!(
            updates.ask(update()).err(),
            Some((Rcode::SERVFAIL, None)),
            "no thread reloading"
        );
        let (reload, wakes) = mpsc::channel();
        updates.connect(reload);
        let answers: Vec<_> = (0..MAX_PENDING)
            .map(|_| updates.ask(update()).unwrap())
            .collect();
        let refused = Some((Rcode::REFUSED, Some(InfoCode::NOT_READY)));
        assert_eq!(updates.ask(update()).err(), refused);
        // One answered and dropped makes room for one.
        let Ok(Wake::Update(asked)) = wakes.try_recv() else {
            unreachable!("an update");
        };
        asked.answer(Rcode::NOERROR);
        drop(asked);
        assert_eq!(answers[0].try_recv(), Ok(Rcode::NOERROR));
        assert!(updates.ask(update()).is_ok());
        assert_eq!(updates.ask(update()).err(), refused);
        // One the thread drops unanswered: the serving thread hears nothing.
        drop(wakes);
        assert!(answers[1].try_recv().is_err());
    }
}
