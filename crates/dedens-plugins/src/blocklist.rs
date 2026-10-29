//! Names refused to clients, and their subdomains (D54), unless an allowlist lets them through (D56).

use std::collections::HashSet;
use std::fmt;
use std::hash::{BuildHasher, BuildHasherDefault, Hasher, RandomState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dedens_proto::edns::InfoCode;
use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{Class, Name, Query, RData, Rcode, Record, RecordType, TextErrorKind, Ttl};
use dedens_server::{Answer, Plugin, Records};

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
    /// The unspecified address, `0.0.0.0` or `::`, to A and AAAA queries; no data to other types.
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
/// Each name is held as a 64-bit hash of its lowercase wire form under a key drawn for these lists (`SipHash`, as
/// std's `HashMap`), 8 bytes instead of the name and its allocation (D58). Two names share a hash with a chance
/// of 2⁻⁶⁴ per pair: a query of a few labels against 2M names hits a name it does not hold once in 10¹² queries,
/// and the key, unknown outside the process, keeps a client from aiming at one.
#[derive(Default)]
pub struct Lists {
    block: Set,
    allow: Set,
    keys: RandomState,
}

/// The hashes of the names of a list.
type Set = HashSet<u64, BuildHasherDefault<Same>>;

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

    /// Adds the names of `text` to `list`: one per line, or lines in the format of `/etc/hosts`
    /// (`0.0.0.0 ads.example`), `#` starting a comment. A name may start with `*.`, as in the lists made for
    /// Blocky (`*.ads.example`), where it means the name and its subdomains, as any name here does. Of hosts
    /// lines, only those of the addresses blocklists use count, `0.0.0.0`, `::`, `127.0.0.1` and `::1`, and of
    /// their names neither addresses, those of one label nor those starting with `localhost`: such files start
    /// with the entries of their host (`127.0.0.1 localhost`, `::1 ip6-loopback`, `0.0.0.0 0.0.0.0`). Lines of
    /// other addresses are left out. Names are host names, not the root: HTML or Adblock rules (`||ads.example^`)
    /// do not read.
    ///
    /// # Errors
    ///
    /// [`ListError::Line`] for a line of a [`Origin::Local`] text that is not a name, [`ListError::NotAList`] for a
    /// [`Origin::Downloaded`] text with no lines or fewer than half of them read; `list` is unchanged then.
    pub fn read(&mut self, list: List, origin: Origin, text: &str) -> Result<Read, ListError> {
        let mut hashes = Vec::new();
        let mut lines = 0;
        let mut skipped = 0;
        for (line, fields) in text::lines(text) {
            lines += 1;
            let before = hashes.len();
            let mut add = |name: &Name<'_>| {
                let mut buf = [0; MAX_NAME_LEN];
                hashes.push(self.keys.hash_one(text::key(name, &mut buf)));
            };
            if let Err(error) = read_line(line, fields, &mut add) {
                match origin {
                    Origin::Local => return Err(error.into()),
                    Origin::Downloaded => {
                        hashes.truncate(before);
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
        let set = match list {
            List::Block => &mut self.block,
            List::Allow => &mut self.allow,
        };
        let mut read = Read {
            skipped,
            ..Read::default()
        };
        set.reserve(hashes.len());
        for hash in hashes {
            if set.insert(hash) {
                read.names += 1;
            } else {
                read.duplicates += 1;
            }
        }
        Ok(read)
    }

    /// How many names `list` holds.
    #[must_use]
    pub fn names(&self, list: List) -> usize {
        match list {
            List::Block => self.block.len(),
            List::Allow => self.allow.len(),
        }
    }

    /// Whether the name `key` is blocked: it or a parent is listed, and neither is allowed.
    fn blocks(&self, key: &[u8]) -> bool {
        let listed = |set: &Set| {
            // Most names are in neither list: the allowlist is looked at only on a hit.
            std::iter::once(key)
                .chain(parents(key))
                .any(|key| set.contains(&self.keys.hash_one(key)))
        };
        listed(&self.block) && !listed(&self.allow)
    }
}

/// Calls `add` with each name of a line, read or not.
fn read_line<'t>(
    line: usize,
    mut fields: impl Iterator<Item = &'t str>,
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

/// The keys of the parents of the name `key`, nearest first, the root left out: a root entry would block every
/// name, and the root name reads as no name.
fn parents(key: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut at = 0;
    std::iter::from_fn(move || {
        let len = *key.get(at)?;
        at += 1 + usize::from(len);
        key.get(at..).filter(|suffix| suffix.len() > 1)
    })
}

/// A plugin answering queries for blocked names as its [`Action`] says; other names, and other classes than IN,
/// go to the next stage.
#[derive(Debug)]
pub struct Blocklist {
    lists: Lists,
    action: Action,
    null_a: Records,
    null_aaaa: Records,
}

impl Blocklist {
    /// Blocks the names of `lists`; `ttl` is that of the records of [`Action::Null`].
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

impl Plugin for Blocklist {
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
        let question = query.question()?;
        let mut buf = [0; MAX_NAME_LEN];
        if question.qclass != Class::IN || !self.lists.blocks(text::key(&question.name, &mut buf)) {
            return None;
        }
        let (rcode, records) = match self.action {
            Action::Nxdomain => (Rcode::NXDOMAIN, None),
            Action::Nodata => (Rcode::NOERROR, None),
            Action::Refused => (Rcode::REFUSED, None),
            Action::Null => (
                Rcode::NOERROR,
                match question.qtype {
                    RecordType::A => Some(&self.null_a),
                    RecordType::AAAA => Some(&self.null_aaaa),
                    _ => None,
                },
            ),
        };
        Some(Answer {
            rcode,
            records,
            authoritative: false,
            error: Some(InfoCode::BLOCKED),
        })
    }
}
