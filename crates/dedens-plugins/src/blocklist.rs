//! Names refused to clients, and their subdomains (D54), unless an allowlist lets them through (D56).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dedens_proto::edns::InfoCode;
use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{Class, Name, Query, RData, Rcode, Record, RecordType, Ttl};
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
#[derive(Debug, Default)]
pub struct Lists {
    block: HashSet<Box<[u8]>>,
    allow: HashSet<Box<[u8]>>,
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
    /// their names neither those of one label nor those starting with `localhost`: such files start with the
    /// entries of their host (`127.0.0.1 localhost`, `::1 ip6-loopback`). Lines of other addresses are left out.
    ///
    /// # Errors
    ///
    /// [`ListError::Line`] for a line of a [`Origin::Local`] text that is not a name, [`ListError::NotAList`] for a
    /// [`Origin::Downloaded`] text with no lines or fewer than half of them read; `list` is unchanged then.
    pub fn read(&mut self, list: List, origin: Origin, text: &str) -> Result<Read, ListError> {
        let mut keys = Vec::new();
        let mut lines = 0;
        let mut skipped = 0;
        let mut buf = [0; MAX_NAME_LEN];
        for (line, fields) in text::lines(text) {
            lines += 1;
            let before = keys.len();
            if let Err(error) = read_line(line, fields, &mut keys, &mut buf) {
                match origin {
                    Origin::Local => return Err(error.into()),
                    Origin::Downloaded => {
                        keys.truncate(before);
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
        set.reserve(keys.len());
        for key in keys {
            if set.insert(key) {
                read.names += 1;
            } else {
                read.duplicates += 1;
            }
        }
        Ok(read)
    }

    /// Drops the blocked names a parent of which is blocked too, as they block nothing more; returns how many.
    pub fn prune(&mut self) -> usize {
        let covered: Vec<Box<[u8]>> = self
            .block
            .iter()
            .filter(|key| parents(key).any(|parent| self.block.contains(parent)))
            .cloned()
            .collect();
        for key in &covered {
            self.block.remove(key);
        }
        covered.len()
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
        let listed = |set: &HashSet<Box<[u8]>>| {
            // Most names are in neither list: the allowlist is looked at only on a hit.
            set.contains(key) || parents(key).any(|parent| set.contains(parent))
        };
        listed(&self.block) && !listed(&self.allow)
    }
}

/// The keys of the names of a line, read or not.
fn read_line<'t>(
    line: usize,
    mut fields: impl Iterator<Item = &'t str>,
    keys: &mut Vec<Box<[u8]>>,
    buf: &mut [u8; MAX_NAME_LEN],
) -> Result<(), LineError> {
    let first = fields.next().unwrap_or_default();
    match first.parse::<IpAddr>() {
        Ok(address) if address.is_unspecified() || address.is_loopback() => {}
        Ok(_) => return Ok(()),
        Err(_) if first.contains('%') => return Ok(()),
        Err(_) => {
            let name = name(line, first)?;
            if let Some(extra) = fields.next() {
                return Err(LineError {
                    line,
                    kind: LineErrorKind::Extra(extra.to_owned()),
                });
            }
            keys.push(text::key(&name, buf).into());
            return Ok(());
        }
    }
    for field in fields {
        let name = name(line, field)?;
        let local = name.label_count() < 2
            || name
                .labels()
                .next()
                .is_some_and(|label| label.eq_ignore_ascii_case(b"localhost"));
        if !local {
            keys.push(text::key(&name, buf).into());
        }
    }
    Ok(())
}

/// `field` without a leading `*.`, as a name.
fn name(line: usize, field: &str) -> Result<Name<'static>, LineError> {
    text::name(line, field.strip_prefix("*.").unwrap_or(field))
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
