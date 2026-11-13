//! Names refused to clients, and their subdomains (D54), unless an allowlist lets them through (D56): the stage
//! that answers and reviews (D118); `lists` holds the names.

mod lists;

use std::net::{Ipv4Addr, Ipv6Addr};

use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, MAX_NAME_LEN, Message, Name, Query, Question, Rcode, Record, RecordType, Ttl,
};
use dedens_server::{Answer, Plugin, Records, Reviewer};

pub use self::lists::{List, ListError, Lists, Merged, Names, Origin, Read, Tlds, host_names};
use crate::text;

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
            // From where the last hop was found, round to it: the order is taken before the hop moves `from`.
            let indexed = records.iter().enumerate();
            for (at, record) in indexed.clone().skip(from).chain(indexed.take(from)) {
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
