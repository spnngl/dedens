//! Names refused to clients, and their subdomains (D54), unless an allowlist lets them through (D56).

use std::collections::HashSet;
use std::fmt;
use std::hash::{BuildHasher, BuildHasherDefault, Hasher, RandomState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dedens_proto::edns::InfoCode;
use dedens_proto::name::{MAX_LABELS, MAX_NAME_LEN};
use dedens_proto::{
    Class, Message, Name, Query, Question, RData, Rcode, Record, RecordType, TextErrorKind, Ttl,
};
use dedens_server::{Answer, Plugin, Records, Reviewer};

use crate::text::{self, LineError, LineErrorKind};

/// The reply to a blocked query, each with the Extended DNS Error Blocked (RFC 8914 §4.16) for clients sending an
/// OPT record, and AA clear: the answer is a policy, not data the server holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(rename_all = "lowercase")
)]
#[non_exhaustive]
pub enum Action {
    /// The name does not exist (RFC 1035 §4.1.1, RFC 8020).
    #[default]
    Nxdomain,
    /// The name has no data of the type (RFC 2308 §2.2).
    Nodata,
    /// The server refuses to answer (RFC 1035 §4.1.1).
    Refused,
    /// The unspecified address, `0.0.0.0` or `::`, to A and AAAA queries of class IN or ANY; no data to other types
    /// and classes.
    Null,
}

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
/// root: `h = SipHash(parent ‖ label)`, the label with its length byte, under a key drawn for these lists (as
/// std's `HashMap`), so that hashing a name hashes each of its suffixes on the way (D110). The key, unknown outside
/// the process, keeps a client from aiming at a collision. A collision at a label carries to the names below it,
/// so two names share a hash with a chance of at most 2⁻⁶⁴ per label: a query of a few labels against 2M names
/// hits a name it does not hold about once in 10¹¹ queries.
#[derive(Default)]
pub struct Lists {
    block: Set,
    allow: Set,
    keys: RandomState,
    tlds: Tlds,
}

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

/// The hashes of the names of a list, and which label counts they have: a suffix of another count is not looked
/// up, and none longer than the longest name is hashed (D110).
#[derive(Default)]
struct Set {
    hashes: HashSet<u64, BuildHasherDefault<Same>>,
    counts: LabelCounts,
}

impl Set {
    fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether a name of `count` labels hashing to `hash` is held.
    fn holds(&self, count: LabelCount, hash: u64) -> bool {
        self.counts.holds(count) && self.hashes.contains(&hash)
    }
}

/// The hasher of [`Set`]: its keys are hashes already, uniform, so a key is its own hash.
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
        let mut counts = LabelCounts::default();
        let (hashes, skipped) = scan(origin, self.tlds, text, |name| {
            let mut buf = [0; MAX_NAME_LEN];
            let (count, hash) = suffixes(&self.keys, text::key(name, &mut buf))
                .last()
                .expect("a name read has a label");
            counts = counts.with(count);
            hash
        })?;
        let set = match list {
            List::Block => &mut self.block,
            List::Allow => &mut self.allow,
        };
        set.counts = set.counts.union(counts);
        let mut read = Read {
            skipped,
            ..Read::default()
        };
        set.hashes.reserve(hashes.len());
        for hash in hashes {
            if set.hashes.insert(hash) {
                read.names += 1;
            } else {
                read.duplicates += 1;
            }
        }
        Ok(read)
    }

    /// Whether a downloaded `text` reads as [`Lists::read`] would read it, without hashing or storing its names:
    /// `names` counts each name read, duplicates included. A line of one label counts: whether it is a name is
    /// the choice of the lists reading the saved copy ([`Tlds`]), not of the download (D118).
    ///
    /// # Errors
    ///
    /// [`ListError::NotAList`] for a text with no lines or fewer than half of them read.
    pub fn check(text: &str) -> Result<Read, ListError> {
        // A vector of `()` counts without allocating.
        let (names, skipped) = scan(Origin::Downloaded, Tlds::Allow, text, |_| ())?;
        Ok(Read {
            names: names.len(),
            duplicates: 0,
            skipped,
        })
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
    fn allows(&self, key: text::Key<'_>) -> bool {
        let longest = self.allow.counts.longest();
        suffixes(&self.keys, key)
            .take_while(|(count, _)| u32::from(count.get()) <= longest)
            .any(|(count, hash)| self.allow.holds(count, hash))
    }

    /// Whether the name `key` is blocked: it or a parent is listed, and neither is allowed. Its suffixes are
    /// hashed from the root, once, as far as the longest name of either list that could still decide.
    fn blocks(&self, key: text::Key<'_>) -> bool {
        // Nothing to block: not even the labels are counted.
        let Some(shortest) = self.block.counts.shortest() else {
            return false;
        };
        let walk = suffixes(&self.keys, key);
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

/// What `each` makes of the names of `text`, read as of `origin`, and the lines skipped: the names of a line that
/// does not read are left out.
fn scan<T>(
    origin: Origin,
    tlds: Tlds,
    text: &str,
    mut each: impl FnMut(&Name<'_>) -> T,
) -> Result<(Vec<T>, usize), ListError> {
    let mut items = Vec::new();
    let mut lines = 0;
    let mut skipped = 0;
    for (line, fields) in text::lines(text) {
        lines += 1;
        let before = items.len();
        if let Err(error) = read_line(line, fields, tlds, &mut |name| items.push(each(name))) {
            match origin {
                Origin::Local => return Err(error.into()),
                Origin::Downloaded => {
                    items.truncate(before);
                    skipped += 1;
                }
            }
        }
    }
    if origin == Origin::Downloaded && (lines == 0 || skipped * 2 > lines) {
        return Err(ListError::NotAList {
            lines,
            read: lines - skipped,
        });
    }
    Ok((items, skipped))
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
                .is_some_and(|label| label.eq_ignore_ascii_case(b"localhost"));
        if !local {
            add(&name);
        }
    }
    Ok(())
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

/// The most hops of a chain that are followed (D118): 16, above any mainstream resolver's chain limit. A response
/// whose chain goes on after them is answered SERVFAIL, its targets past the first hop beyond unchecked: a client
/// following it would reach names nobody looked up.
pub const MAX_HOPS: usize = 16;

/// A plugin answering queries for blocked names as its [`Action`] says, whatever their class (D110); other names go
/// to the next stage. It also reviews the responses of the stages after it (D118): one whose chain of CNAME and
/// DNAME records, followed from the query name, leads to a blocked name is answered as a query for it is, so that a
/// name cannot be reached by a CNAME to a blocked one, as `t.site. CNAME ads.example.`. The names are checked as
/// the query name is, the allowlist included, and a query name the allowlist lets through is not reviewed.
#[derive(Debug)]
pub struct Blocklist {
    lists: Lists,
    action: Action,
    null_a: Records,
    null_aaaa: Records,
}

impl Blocklist {
    /// Blocks the names of `lists`, and the responses whose CNAME and DNAME targets are blocked (up to
    /// [`MAX_HOPS`] of them); `ttl` is that of the records of [`Action::Null`].
    ///
    /// # Panics
    ///
    /// Never: the records of [`Action::Null`] are one address each.
    #[must_use]
    pub fn new(lists: Lists, action: Action, ttl: Ttl) -> Self {
        // One record owned by the question's name: its owner is a pointer to the question, whatever its name.
        let null = |data: RData<'static>| {
            let name = Name::from_labels([&b"blocked"[..]]).expect("a name of one short label");
            let record = Record::new(name.clone(), Class::IN, ttl, &data);
            Records::new(&name, &[record]).expect("one address record fits a message")
        };
        Self {
            lists,
            action,
            null_a: null(RData::A(Ipv4Addr::UNSPECIFIED)),
            null_aaaa: null(RData::Aaaa(Ipv6Addr::UNSPECIFIED)),
        }
    }
}

impl Blocklist {
    fn blocks(&self, name: &Name<'_>) -> bool {
        let mut buf = [0; MAX_NAME_LEN];
        self.lists.blocks(text::key(name, &mut buf))
    }

    /// Whether the name is allowed, itself or a parent.
    fn allows(&self, name: &Name<'_>) -> bool {
        let mut buf = [0; MAX_NAME_LEN];
        self.lists.allows(text::key(name, &mut buf))
    }

    /// SERVFAIL for a chain over [`MAX_HOPS`]: not blocked, and not a response to serve.
    const fn too_long() -> Answer<'static> {
        Answer {
            rcode: Rcode::SERVFAIL,
            records: None,
            authoritative: false,
            error: Some(InfoCode::OTHER),
        }
    }

    /// The reply to a query for a blocked name, `question` being the client's.
    fn blocked(&self, question: &Question<'_>) -> Answer<'_> {
        let (rcode, records) = match self.action {
            Action::Nxdomain => (Rcode::NXDOMAIN, None),
            Action::Nodata => (Rcode::NOERROR, None),
            Action::Refused => (Rcode::REFUSED, None),
            Action::Null => (
                Rcode::NOERROR,
                // The records are of class IN: no data to a question of another class.
                match (question.qclass, question.qtype) {
                    (Class::IN | Class::ANY, RecordType::A) => Some(&self.null_a),
                    (Class::IN | Class::ANY, RecordType::AAAA) => Some(&self.null_aaaa),
                    _ => None,
                },
            ),
        };
        Answer {
            rcode,
            records,
            authoritative: false,
            error: Some(InfoCode::BLOCKED),
        }
    }
}

impl Plugin for Blocklist {
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
        let question = query.question()?;
        self.blocks(&question.name).then(|| self.blocked(question))
    }

    /// Only with names to block: a response is not decoded for nothing.
    fn reviewer(&self) -> Option<&dyn Reviewer> {
        (self.lists.names(List::Block) > 0).then_some(self)
    }
}

impl Reviewer for Blocklist {
    /// Follows the chain of CNAME records from the query name, a hop for each owned by the name reached, and checks
    /// each target, and the target of each DNAME above that name: the DNAME and the CNAME synthesized from it
    /// (RFC 6672 §2.2) make one hop. Records on no chain are ignored, and so is a second CNAME of a name
    /// (RFC 1034 §3.6.2 allows one). At most [`MAX_HOPS`] hops. A chain is written in order, so each hop starts
    /// reading where the last was found and stops at its CNAME: a response costs its records, not [`MAX_HOPS`]
    /// times them, unless it holds a DNAME, which asks the whole section at each hop.
    fn review(&self, query: &Query<'_>, response: &Message<'_>) -> Option<Answer<'_>> {
        let question = query.question()?;
        if self.allows(&question.name) {
            return None;
        }
        let records = &response.answer;
        let whole = records.iter().any(|r| r.rtype() == RecordType::DNAME);
        let mut current = question.name.clone();
        let mut from = 0;
        for _ in 0..=MAX_HOPS {
            let mut next = None;
            for offset in 0..records.len() {
                let at = (from + offset) % records.len();
                let Some(record) = records.get(at) else {
                    break;
                };
                let target = match record.rtype() {
                    RecordType::CNAME if next.is_none() && record.name == current => {
                        match record.data() {
                            RData::Cname(target) => {
                                from = at + 1;
                                target
                            }
                            _ => continue,
                        }
                    }
                    // The target of a DNAME above `current`, not `current` itself (RFC 6672 §2.1): the rewrite of
                    // the names below its owner.
                    RecordType::DNAME
                        if current.is_within(&record.name) && current != record.name =>
                    {
                        match record.data() {
                            RData::Opaque(data) => match Name::from_uncompressed(data.data()) {
                                Ok(target) if self.blocks(&target) => {
                                    return Some(self.blocked(question));
                                }
                                _ => continue,
                            },
                            _ => continue,
                        }
                    }
                    _ => continue,
                };
                if self.blocks(&target) {
                    return Some(self.blocked(question));
                }
                next = Some(target);
                if !whole {
                    break;
                }
            }
            current = next?;
        }
        Some(Self::too_long())
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{BuildHasher, BuildHasherDefault};

    use super::Same;

    /// A key is a hash already: it is its own.
    #[test]
    fn a_key_is_its_own_hash() {
        let same = BuildHasherDefault::<Same>::default();
        assert_eq!(
            same.hash_one(0x0123_4567_89ab_cdef_u64),
            0x0123_4567_89ab_cdef
        );
    }
}
