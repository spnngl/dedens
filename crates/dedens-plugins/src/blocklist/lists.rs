//! The names of a blocklist and of its allowlist (D54, D56): each text read once into [`Names`] (D120), each side
//! merged into one [`Merged`] set of hashes (D110), a name matching itself and its subdomains without regard to case
//! (RFC 4343 §3).

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::fmt;
use std::hash::{BuildHasher, BuildHasherDefault, Hasher, RandomState};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, LazyLock};

use dedens_proto::{MAX_LABELS, MAX_NAME_LEN, Name, TextErrorKind};

use crate::text::{self, LineError, LineErrorKind};

/// The list a text adds names to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    /// Names blocked with their subdomains.
    Block,
    /// Names, with their subdomains, never blocked.
    Allow,
}

/// Where a text comes from, which decides what a line that is not a name does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The server's own configuration: such a line is an error to fix.
    Local,
    /// Downloaded, someone else's list: such lines are skipped, and the text is refused when it has no lines or
    /// fewer than half of them read, as an error page served with status 200 does.
    Downloaded,
}

/// Whether a plain line of one label (`zip`) is a name: it lists a whole top-level domain (D118).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Tlds {
    /// Such a line is refused: a mistake blocking `com` is not worth the lists that would hold one.
    #[default]
    Refuse,
    /// Such a line is a name, for lists of top-level domains (`zip`, `mov`).
    Allow,
}

/// What reading a text added.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Read {
    /// Names new to the list.
    pub names: usize,
    /// Names the list held already.
    pub duplicates: usize,
    /// Lines skipped, of a downloaded text.
    pub skipped: usize,
}

/// A text [`Lists::read`] refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ListError {
    /// A line of a local text that is not a name.
    #[error(transparent)]
    Line(#[from] LineError),
    /// A downloaded text with no lines, or fewer than half of them read.
    #[error("not a list: {read} of {lines} lines read")]
    NotAList {
        /// Its lines, comments and blank lines left out.
        lines: usize,
        /// Those read.
        read: usize,
    },
}

/// The names of a blocklist and of its allowlist, each matching itself and its subdomains without regard to case
/// (RFC 4343 §3).
///
/// Each name is held as a 64-bit hash, 8 bytes instead of the name and its allocation (D58), chained from the
/// root: `h = SipHash(parent ‖ label)`, the label with its length byte, under a key drawn once for the process
/// (as std's `HashMap` draws its own), so that hashing a name hashes each of its suffixes on the way (D110). The
/// key, unknown outside the process, keeps a client from aiming at a collision, and the same for every list, so
/// that the [`Names`] of a text fit any `Lists` (D120). A collision at a label carries to the names below it, so
/// two names share a hash with a chance of at most 2⁻⁶⁴ per label: a query of a few labels against 2M names hits
/// a name it does not hold about once in 10¹¹ queries.
///
/// Each side is one [`Merged`] set, however many texts it was read from (D120): a lookup asks one set, as D110
/// counts it.
#[derive(Default)]
pub struct Lists {
    block: Merged,
    allow: Merged,
    tlds: Tlds,
}

/// The key of every hash of every list (D120).
static KEYS: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// How many labels a name of a list has: from 1, the root being no name, to [`MAX_LABELS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LabelCount(u8);

impl LabelCount {
    fn new(labels: u8) -> Option<Self> {
        (1..=MAX_LABELS)
            .contains(&usize::from(labels))
            .then_some(Self(labels))
    }

    const fn get(self) -> u8 {
        self.0
    }
}

/// The label counts of a set of names, a bit each.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LabelCounts(u128);

impl LabelCounts {
    const fn with(self, count: LabelCount) -> Self {
        Self(self.0 | 1 << count.get())
    }

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn holds(self, count: LabelCount) -> bool {
        self.0 >> count.get() & 1 == 1
    }

    /// The fewest labels of a name, none for no names.
    const fn shortest(self) -> Option<u32> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros())
        }
    }

    /// The most labels of a name, 0 for no names.
    fn longest(self) -> u32 {
        self.0.checked_ilog2().unwrap_or(0)
    }
}

/// The hashes of the names of a text, sorted, each once, and which label counts they have (D120): 8 bytes a name,
/// what a reload keeps of a text that did not change.
struct Hashes {
    sorted: Box<[u64]>,
    counts: LabelCounts,
}

impl Hashes {
    fn new(mut hashes: Vec<u64>, counts: LabelCounts) -> Self {
        hashes.sort_unstable();
        hashes.dedup();
        Self {
            sorted: hashes.into_boxed_slice(),
            counts,
        }
    }
}

impl Hashes {
    fn len(&self) -> usize {
        self.sorted.len()
    }
}

impl fmt::Debug for Hashes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hashes")
            .field("names", &self.len())
            .finish_non_exhaustive()
    }
}

type HashSetOf = HashSet<u64, BuildHasherDefault<Same>>;

/// One side of lists, block or allow: the names of any number of texts as one set of hashes, and which label counts
/// they have, so that a suffix of another count is not looked up, and none longer than the longest name is hashed
/// (D110). Cloning is cheap: the set is shared, so that stages reading the same texts hold one (D120).
#[derive(Clone, Default)]
pub struct Merged {
    hashes: Arc<HashSetOf>,
    counts: LabelCounts,
    /// Names listed more than once, in a text or across texts.
    duplicates: usize,
}

impl Merged {
    /// The names of `sources`, read as lists reading plain lines of one label as `tlds` says, in one set sized
    /// for the names they hold together, each once (D120).
    ///
    /// # Errors
    ///
    /// [`ListError::NotAList`] for a downloaded text that [`Names::check`] refuses.
    pub fn new(tlds: Tlds, sources: &[Names]) -> Result<Self, ListError> {
        let mut text_duplicates = Vec::with_capacity(sources.len());
        for names in sources {
            text_duplicates.push(names.check(tlds)?.duplicates);
        }
        let parts: Vec<&[u64]> = sources
            .iter()
            .flat_map(|names| names.included(tlds))
            .map(|hashes| &*hashes.sorted)
            .collect();
        let capacity = union_len(&parts);
        let mut merged = Self {
            hashes: Arc::new(HashSet::with_capacity_and_hasher(
                capacity,
                BuildHasherDefault::default(),
            )),
            ..Self::default()
        };
        for (names, duplicates) in sources.iter().zip(text_duplicates) {
            merged.insert(tlds, names, duplicates);
        }
        Ok(merged)
    }

    /// Whether `self` and `other` are one set, shared: a clone, not a set built twice.
    #[must_use]
    pub fn shares(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.hashes, &other.hashes)
    }

    /// How many names it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether it holds no name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// How many names were listed more than once.
    #[must_use]
    pub const fn duplicates(&self) -> usize {
        self.duplicates
    }

    /// Whether a name of `count` labels hashing to `hash` is held.
    fn holds(&self, count: LabelCount, hash: u64) -> bool {
        self.counts.holds(count) && self.hashes.contains(&hash)
    }

    /// Adds the names of `names` read as `tlds` says, of which `duplicates` were listed twice in the text, and
    /// returns how many the set held already.
    fn insert(&mut self, tlds: Tlds, names: &Names, duplicates: usize) -> usize {
        let hashes = Arc::make_mut(&mut self.hashes);
        let mut held = 0;
        for part in names.included(tlds) {
            self.counts = self.counts.union(part.counts);
            for &hash in &*part.sorted {
                held += usize::from(!hashes.insert(hash));
            }
        }
        self.duplicates += duplicates + held;
        held
    }
}

/// How many hashes the sorted `parts` hold together, each once: a merge of them, nothing held.
fn union_len(parts: &[&[u64]]) -> usize {
    let mut next = vec![0; parts.len()];
    let mut heads = BinaryHeap::new();
    for (part, hashes) in parts.iter().enumerate() {
        if let Some(&hash) = hashes.first() {
            heads.push(Reverse((hash, part)));
        }
    }
    let mut len = 0;
    let mut last = None;
    while let Some(Reverse((hash, part))) = heads.pop() {
        if last != Some(hash) {
            len += 1;
            last = Some(hash);
        }
        next[part] += 1;
        if let Some(&hash) = parts[part].get(next[part]) {
            heads.push(Reverse((hash, part)));
        }
    }
    len
}

/// The hasher of [`Merged`]: its keys are hashes already, uniform, so a key is its own hash.
#[derive(Default)]
struct Same(u64);

impl Hasher for Same {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(byte);
        }
    }

    fn write_u64(&mut self, hash: u64) {
        self.0 = hash;
    }
}

impl fmt::Debug for Merged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Merged")
            .field("names", &self.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Lists {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lists")
            .field("block", &self.block.len())
            .field("allow", &self.allow.len())
            .finish_non_exhaustive()
    }
}

impl Lists {
    /// Empty lists.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty lists reading plain lines of one label as `tlds` says.
    #[must_use]
    pub fn with_tlds(tlds: Tlds) -> Self {
        Self {
            tlds,
            ..Self::default()
        }
    }

    /// Adds the names of `text` to `list`: one per line, or lines in the format of `/etc/hosts`
    /// (`0.0.0.0 ads.example`), `#` starting a comment. A name may start with `*.`, as in the lists made for
    /// Blocky (`*.ads.example`), where it means the name and its subdomains, as any name here does. Of hosts
    /// lines, only those of the addresses blocklists use count, `0.0.0.0`, `::`, `127.0.0.1` and `::1`, and of
    /// their names neither addresses, those of one label nor those starting with `localhost`: such files start
    /// with the entries of their host (`127.0.0.1 localhost`, `::1 ip6-loopback`, `0.0.0.0 0.0.0.0`). Lines of
    /// other addresses are left out. Names are host names, not the root: HTML or Adblock rules (`||ads.example^`)
    /// do not read. A plain line of one label (`com`) does not read either, as it would list a whole top-level
    /// domain, unless the lists were made [`Lists::with_tlds`] [`Tlds::Allow`] (D118); hosts lines are the
    /// exception, their one-label names being the host's own.
    ///
    /// # Errors
    ///
    /// [`ListError::Line`] for a line of a [`Origin::Local`] text that is not a name, [`ListError::NotAList`] for a
    /// [`Origin::Downloaded`] text with no lines or fewer than half of them read; `list` is unchanged then.
    ///
    /// # Panics
    ///
    /// Never: a name read has a label.
    pub fn read(&mut self, list: List, origin: Origin, text: &str) -> Result<Read, ListError> {
        let names = match origin {
            Origin::Local => Names::local(self.tlds, text)?,
            Origin::Downloaded => Names::downloaded(text),
        };
        self.add(list, &names)
    }

    /// Adds `names`, a text read already, to `list`: what [`Lists::read`] does after reading, so that a text read
    /// once can be added to the lists of any number of stages (D120). A downloaded text is judged as these lists
    /// read plain lines of one label ([`Names::check`]); a local one was read as its `tlds` said.
    ///
    /// # Errors
    ///
    /// [`ListError::NotAList`] for a downloaded text with no lines or fewer than half of them read; `list` is
    /// unchanged then.
    pub fn add(&mut self, list: List, names: &Names) -> Result<Read, ListError> {
        let read = names.check(self.tlds)?;
        let side = match list {
            List::Block => &mut self.block,
            List::Allow => &mut self.allow,
        };
        let held = side.insert(self.tlds, names, read.duplicates);
        Ok(Read {
            names: read.names - held,
            duplicates: read.duplicates + held,
            skipped: read.skipped,
        })
    }

    /// Lists reading plain lines of one label as `tlds` says, of the sides `block` and `allow` made once from the
    /// texts of a stage ([`Merged::new`]).
    #[must_use]
    pub fn from_merged(tlds: Tlds, block: Merged, allow: Merged) -> Self {
        Self { block, allow, tlds }
    }

    /// How many names of `list` were listed more than once, in a text or across texts.
    #[must_use]
    pub fn duplicates(&self, list: List) -> usize {
        match list {
            List::Block => self.block.duplicates,
            List::Allow => self.allow.duplicates,
        }
    }

    /// How many names `list` holds.
    #[must_use]
    pub fn names(&self, list: List) -> usize {
        match list {
            List::Block => self.block.len(),
            List::Allow => self.allow.len(),
        }
    }

    /// Whether the name `key` or a parent is allowed.
    pub(super) fn allows(&self, key: text::Key<'_>) -> bool {
        let longest = self.allow.counts.longest();
        suffixes(&KEYS, key)
            .take_while(|(count, _)| u32::from(count.get()) <= longest)
            .any(|(count, hash)| self.allow.holds(count, hash))
    }

    /// Whether the name `key` is blocked: it or a parent is listed, and neither is allowed. Its suffixes are
    /// hashed from the root, once, as far as the longest name of either list that could still decide.
    pub(super) fn blocks(&self, key: text::Key<'_>) -> bool {
        // Nothing to block: not even the labels are counted.
        let Some(shortest) = self.block.counts.shortest() else {
            return false;
        };
        let walk = suffixes(&KEYS, key);
        if u32::from(walk.labels()) < shortest {
            return false;
        }
        let mut blocked = false;
        for (count, hash) in walk {
            if self.allow.holds(count, hash) {
                return false;
            }
            blocked |= self.block.holds(count, hash);
            // Once blocked, only an allowed parent matters; before, only a blocked one.
            let limit = if blocked {
                self.allow.counts.longest()
            } else {
                self.block.counts.longest()
            };
            if u32::from(count.get()) >= limit {
                break;
            }
        }
        blocked
    }
}

/// The names of one text, read once: the hashes of what [`Lists::read`] would add, kept as a set of their own, so
/// that the text is read again only when it changes, and the stages naming it share the set (D120). Cloning is
/// cheap: the sets are shared.
///
/// A plain line of one label (`zip`) is kept apart, in a set of top-level domains: whether it is a name is the
/// choice of the [`Lists`] adding the text ([`Tlds`]), so a downloaded text is read the same for every stage.
#[derive(Debug, Clone)]
pub struct Names {
    origin: Origin,
    plain: Arc<Hashes>,
    tlds: Arc<Hashes>,
    /// Names the text listed twice, those of one label apart.
    duplicates: usize,
    /// Lines of names or hosts, comments and blank lines left out.
    lines: usize,
    /// Lines of a downloaded text that did not read.
    skipped: usize,
    /// Plain lines of one label read, duplicates included.
    singles: usize,
}

impl Names {
    /// Reads a [`Origin::Local`] text as [`Lists::read`] does: plain lines of one label are errors unless `tlds`
    /// allows them.
    ///
    /// # Errors
    ///
    /// [`ListError::Line`] for a line that is not a name.
    pub fn local(tlds: Tlds, text: &str) -> Result<Self, ListError> {
        Self::parse(Origin::Local, tlds, text).map_err(ListError::from)
    }

    /// Reads a [`Origin::Downloaded`] text, skipping the lines that are not names; [`Names::check`] says whether
    /// it is a list.
    ///
    /// # Panics
    ///
    /// Never: a downloaded text has no error, its lines that do not read are skipped.
    #[must_use]
    pub fn downloaded(text: &str) -> Self {
        Self::parse(Origin::Downloaded, Tlds::Allow, text)
            .expect("a downloaded text skips its errors")
    }

    fn parse(origin: Origin, tlds: Tlds, text: &str) -> Result<Self, LineError> {
        let scanned = scan(origin, tlds, text)?;
        let singles = scanned.singles.len();
        let listed = scanned.plain.len();
        let plain = Hashes::new(scanned.plain, scanned.counts);
        let tlds = Hashes::new(scanned.singles, LabelCounts::default().with(LabelCount(1)));
        Ok(Self {
            origin,
            duplicates: listed - plain.len(),
            plain: Arc::new(plain),
            tlds: Arc::new(tlds),
            lines: scanned.lines,
            skipped: scanned.skipped,
            singles,
        })
    }

    /// Whether `self` and `other` are one reading, shared: a clone, not a text read twice.
    #[must_use]
    pub fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.plain, &other.plain) && Arc::ptr_eq(&self.tlds, &other.tlds)
    }

    /// How many names the text holds, duplicates left out.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plain.len() + self.tlds.len()
    }

    /// Whether the text holds no name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The sets of hashes the text adds to lists reading plain lines of one label as `tlds` says: its names, and
    /// its top-level domains if `tlds` lets them count. A local text read as another `tlds` said has none of them.
    fn included(&self, tlds: Tlds) -> impl Iterator<Item = &Hashes> {
        let tlds = (tlds == Tlds::Allow).then_some(&*self.tlds);
        std::iter::once(&*self.plain)
            .chain(tlds)
            .filter(|hashes| hashes.len() > 0)
    }

    /// What adding the text to lists reading plain lines of one label as `tlds` says would read, before the names
    /// the lists hold are left out: `names` and `duplicates` of this text alone.
    ///
    /// # Errors
    ///
    /// [`ListError::NotAList`] for a downloaded text with no lines or fewer than half of them read.
    pub fn check(&self, tlds: Tlds) -> Result<Read, ListError> {
        let with_tlds = tlds == Tlds::Allow;
        let skipped = if with_tlds {
            self.skipped
        } else {
            self.skipped + self.singles
        };
        if self.origin == Origin::Downloaded && (self.lines == 0 || skipped * 2 > self.lines) {
            return Err(ListError::NotAList {
                lines: self.lines,
                read: self.lines - skipped,
            });
        }
        let (names, duplicates) = if with_tlds {
            (
                self.plain.len() + self.tlds.len(),
                self.duplicates + self.singles - self.tlds.len(),
            )
        } else {
            (self.plain.len(), self.duplicates)
        };
        Ok(Read {
            names,
            duplicates,
            skipped,
        })
    }
}

/// The suffixes of a name, from the root out, the root left out: a root entry would block every name, and the
/// root name reads as no name.
fn suffixes<'k>(keys: &'k RandomState, key: text::Key<'k>) -> Suffixes<'k> {
    let key = key.as_bytes();
    // Where each label starts: suffixes are found from the end, but labels only from the front.
    let mut starts = [0; MAX_LABELS];
    let mut total = 0;
    let mut at = 0;
    while let Some(&len) = key.get(at).filter(|&&len| len != 0)
        && let Some(slot) = starts.get_mut(usize::from(total))
        && let Ok(start) = u8::try_from(at)
    {
        *slot = start;
        total += 1;
        at += 1 + usize::from(len);
    }
    Suffixes {
        keys,
        key,
        starts,
        total,
        visited: 0,
        hash: 0,
    }
}

/// The suffixes of a name with their label counts and hashes, nearest to the root first (see [`suffixes`]): each
/// hash chains the one before it, so the walk costs one short hash per suffix.
struct Suffixes<'k> {
    keys: &'k RandomState,
    key: &'k [u8],
    starts: [u8; MAX_LABELS],
    total: u8,
    visited: u8,
    hash: u64,
}

impl Suffixes<'_> {
    /// How many labels the name has.
    const fn labels(&self) -> u8 {
        self.total
    }
}

impl Iterator for Suffixes<'_> {
    type Item = (LabelCount, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let visited = self.visited.checked_add(1)?;
        let start = *self
            .starts
            .get(usize::from(self.total.checked_sub(visited)?))?;
        let rest = self.key.get(usize::from(start)..)?;
        let label = rest.get(..=usize::from(*rest.first()?))?;
        let mut hasher = self.keys.build_hasher();
        hasher.write_u64(self.hash);
        hasher.write(label);
        self.hash = hasher.finish();
        self.visited = visited;
        Some((LabelCount::new(visited)?, self.hash))
    }
}

/// The hashes of the names of `text`, read as of `origin`, and the lines it had and skipped: the names of a line that
/// does not read are left out, whole.
fn scan(origin: Origin, tlds: Tlds, text: &str) -> Result<Scanned, LineError> {
    let mut scanned = Scanned::default();
    // The names of the line being read, added to the text's only once the whole line has read.
    let mut line_names = Vec::new();
    let mut buf = [0; MAX_NAME_LEN];
    for (line, fields) in text::lines(text) {
        scanned.lines += 1;
        line_names.clear();
        let add = &mut |name: &Name<'_>| {
            line_names.extend(suffixes(&KEYS, text::key(name, &mut buf)).last());
        };
        match read_line(line, fields, tlds, add) {
            Ok(()) => {
                for &(count, hash) in &line_names {
                    if count.get() == 1 {
                        scanned.singles.push(hash);
                    } else {
                        scanned.plain.push(hash);
                        scanned.counts = scanned.counts.with(count);
                    }
                }
            }
            Err(error) => match origin {
                Origin::Local => return Err(error),
                Origin::Downloaded => scanned.skipped += 1,
            },
        }
    }
    Ok(scanned)
}

/// What [`scan`] read.
#[derive(Default)]
struct Scanned {
    /// The hashes of the names of two labels or more, as listed.
    plain: Vec<u64>,
    /// Their label counts.
    counts: LabelCounts,
    /// The hashes of the plain lines of one label, as listed: whether they are names is for the lists to say.
    singles: Vec<u64>,
    /// Lines of names or hosts.
    lines: usize,
    /// Lines of a downloaded text that did not read.
    skipped: usize,
}

/// Calls `add` with each name of a line, read or not.
fn read_line<'t>(
    line: usize,
    mut fields: impl Iterator<Item = &'t str>,
    tlds: Tlds,
    add: &mut impl FnMut(&Name<'_>),
) -> Result<(), LineError> {
    let first = fields.next().unwrap_or_default();
    match first.parse::<IpAddr>() {
        Ok(address) if address.is_unspecified() || address.is_loopback() => {}
        Ok(_) => return Ok(()),
        // An address with a zone (`fe80::1%lo0 localhost`), of the host's own entries.
        Err(_)
            if first
                .split_once('%')
                .is_some_and(|(address, _)| address.parse::<Ipv6Addr>().is_ok()) =>
        {
            return Ok(());
        }
        Err(_) => {
            let name = name(line, first)?;
            if name.label_count() < 2 && tlds == Tlds::Refuse {
                return Err(LineError {
                    line,
                    kind: LineErrorKind::SingleLabel(first.to_owned()),
                });
            }
            if let Some(extra) = fields.next() {
                return Err(LineError {
                    line,
                    kind: LineErrorKind::Extra(extra.to_owned()),
                });
            }
            add(&name);
            return Ok(());
        }
    }
    for field in fields {
        // An address as a name, of the host's own entries (`0.0.0.0 0.0.0.0`).
        if field.parse::<IpAddr>().is_ok() {
            continue;
        }
        let name = name(line, field)?;
        let local = name.label_count() < 2
            || name
                .labels()
                .next()
                .and_then(|label| label.get(..b"localhost".len()))
                .is_some_and(|start| start.eq_ignore_ascii_case(b"localhost"));
        if !local {
            add(&name);
        }
    }
    Ok(())
}

/// The names of `text`, one a line, `#` starting a comment, each read as a plain line of a blocklist is (D56, D96)
/// but for the rule against one label: a name to ask for is no list of names. A `*.name` is refused, as a wildcard
/// cannot be asked.
///
/// # Errors
///
/// [`LineError`] for a line that is not a host name, is a wildcard, or holds more than a name.
pub fn host_names(text: &str) -> Result<Vec<Name<'static>>, LineError> {
    let mut names = Vec::new();
    for (line, mut fields) in text::lines(text) {
        let field = fields.next().unwrap_or_default();
        if let Some(extra) = fields.next() {
            return Err(LineError {
                line,
                kind: LineErrorKind::Extra(extra.to_owned()),
            });
        }
        if field.starts_with("*.") {
            return Err(LineError {
                line,
                kind: LineErrorKind::Wildcard(field.to_owned()),
            });
        }
        names.push(name(line, field)?);
    }
    Ok(names)
}

/// `field` as a host name, after an optional `*.`: labels of ASCII letters, digits, `-` and `_` (`_dmarc`)
/// between dots, one of them not all digits so that no address reads as a name, and an optional trailing dot. No
/// escapes, and no root (`.`, `@`): HTML, Adblock rules (`||name^`), URLs and `host:port` do not read, so an error
/// page is no list.
fn name(line: usize, field: &str) -> Result<Name<'static>, LineError> {
    let host = field.strip_prefix("*.").unwrap_or(field);
    let host = host.strip_suffix('.').unwrap_or(host);
    let error = |kind| LineError {
        line,
        kind: LineErrorKind::Name(field.to_owned(), kind),
    };
    let label = |label: &str| {
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    let digits = |label: &str| label.bytes().all(|byte| byte.is_ascii_digit());
    if !host.split('.').all(label) || host.split('.').all(digits) {
        return Err(error(TextErrorKind::Invalid("host name")));
    }
    Name::from_labels(host.split('.').map(str::as_bytes)).map_err(|e| error(TextErrorKind::Name(e)))
}

#[cfg(test)]
mod tests {
    use std::hash::{BuildHasher, BuildHasherDefault};

    use super::{Same, union_len};

    /// A key is a hash already: it is its own.
    #[test]
    fn a_key_is_its_own_hash() {
        let same = BuildHasherDefault::<Same>::default();
        assert_eq!(
            same.hash_one(0x0123_4567_89ab_cdef_u64),
            0x0123_4567_89ab_cdef
        );
    }

    /// The size of a merged set is that of the union of its parts: each hash once, however many parts hold it.
    #[test]
    fn the_union_counts_each_hash_once() {
        assert_eq!(union_len(&[&[1, 3, 5], &[2, 3], &[], &[5, 8]]), 5);
        assert_eq!(union_len(&[]), 0);
    }
}
