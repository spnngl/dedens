//! [`Zone::answer`]: what a zone says to one question, RFC 1034 §4.3.2 without DNSSEC (D206).

use std::borrow::Cow;

use dedens_proto::{Class, MAX_NAME_LEN, Name, Question, Rcode, RecordType};

use crate::{Kind, Node, RrSet, Zone};

/// The most CNAME and DNAME links one answer follows: 11, what a dedens resolver accepts in a response
/// (`dedens_resolver::scrub::MAX_CHAIN`). Knot stops at 5 and NSD at 18. A chain that goes on ends in
/// [`End::Open`]: the client asks again from there.
pub const MAX_CHAIN: usize = 11;

/// A name of the zone as stored, with its node.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// The name, in the case of the zone file.
    pub name: &'a Name<'static>,
    /// What the zone holds there.
    pub node: &'a Node,
}

/// How a name asked about was found in the zone.
#[derive(Debug, Clone, Copy)]
pub enum Match<'a> {
    /// The zone has the name.
    Exact(Entry<'a>),
    /// The zone has no such name: the wildcard `source` answers for it, the name's closest encloser being
    /// `encloser` (RFC 4592 §2.2.1).
    Wildcard {
        /// The wildcard owner, `*.` and the encloser.
        source: Entry<'a>,
        /// The closest encloser.
        encloser: Entry<'a>,
    },
}

impl<'a> Match<'a> {
    /// The node that holds the data: the name's own, or the wildcard's.
    #[must_use]
    pub const fn node(&self) -> &'a Node {
        match self {
            Self::Exact(entry) | Self::Wildcard { source: entry, .. } => entry.node,
        }
    }
}

/// One step of a chain of aliases.
#[derive(Debug, Clone)]
pub enum Link<'a> {
    /// `name` is an alias: the CNAME of `at` is in the answer (RFC 1034 §3.6.2); the chain goes on at its target.
    Cname {
        /// The name that leads to the alias, as asked or as the alias before it gave it.
        name: Name<'a>,
        /// Where the CNAME was found.
        at: Match<'a>,
        /// The CNAME `RRset`.
        rrset: &'a RrSet,
    },
    /// `name` is below a DNAME: it is in the answer with the CNAME synthesised from it, which has the name as
    /// owner and the DNAME's TTL (RFC 6672 §3.1); the chain goes on at `target`.
    Dname {
        /// The name below the DNAME.
        name: Name<'a>,
        /// The DNAME owner.
        at: Entry<'a>,
        /// The DNAME `RRset`.
        rrset: &'a RrSet,
        /// The name with the DNAME's owner replaced by its target, the CNAME's RDATA.
        target: Name<'static>,
    },
}

impl<'a> Link<'a> {
    /// The name the link leaves from.
    const fn name(&self) -> &Name<'a> {
        match self {
            Self::Cname { name, .. } | Self::Dname { name, .. } => name,
        }
    }
}

/// Where the way from the name asked ends.
#[derive(Debug, Clone)]
pub enum End<'a> {
    /// The zone is not the authority for the name, or serves another class (RFC 1034 §4.3.1): REFUSED.
    NotAuth,
    /// The `RRset` asked for, from `at`, owned by `name`; for ANY the one of the lowest type (RFC 8482 §4.2),
    /// for RRSIG the first signature set.
    Data {
        /// The owner in the answer: the name asked, as asked, also for a wildcard.
        name: Name<'a>,
        /// Where the data is.
        at: Match<'a>,
        /// The type of `rrset`.
        rtype: RecordType,
        /// The records.
        rrset: &'a RrSet,
    },
    /// The name exists, with no `RRset` of the type asked, or is an empty non-terminal (RFC 2308 §2.2): NOERROR
    /// with the SOA.
    NoData {
        /// The name asked.
        name: Name<'a>,
        /// Where it was found.
        at: Match<'a>,
    },
    /// No name of the zone matches, and no wildcard (RFC 2308 §2.1): NXDOMAIN with the SOA.
    NxDomain {
        /// The name asked.
        name: Name<'a>,
        /// Its closest encloser, which a proof of non-existence needs (RFC 4592 §3.3.1).
        encloser: Entry<'a>,
    },
    /// The name is at or below the delegation point `cut`, whose NS `RRset` is the answer (RFC 1034 §4.3.2
    /// step 3b); a DS asked at the delegation point is data instead (RFC 4035 §3.1.4.1).
    Referral {
        /// The delegation point.
        cut: Entry<'a>,
    },
    /// The name is below a DNAME whose target would make a name longer than 255 bytes: YXDOMAIN with the DNAME
    /// (RFC 6672 §2.2).
    YxDomain {
        /// The name asked.
        name: Name<'a>,
        /// The DNAME owner.
        at: Entry<'a>,
        /// The DNAME `RRset`.
        rrset: &'a RrSet,
    },
    /// The CNAME asked for is the one synthesised by the last link (RFC 6672 §3.2).
    Synthesized,
    /// The chain goes on at `name`, which this answer does not resolve: out of the zone, past [`MAX_CHAIN`], or
    /// back to a link it has.
    Open {
        /// Where the chain goes on.
        name: Name<'a>,
    },
}

/// The answer of a zone to a question: the links of CNAME and DNAME followed, and where they end.
///
/// A chain ends in any of the other outcomes, so the CNAME and DNAME answers of RFC 1034 §4.3.2 are
/// [`Link`]s rather than ends. Sections are built by [`Answer::fill`](crate::Answer::fill).
#[derive(Debug, Clone)]
pub struct Answer<'a> {
    /// The aliases followed, in order; none when the name asked is not one.
    pub chain: Vec<Link<'a>>,
    /// Where the last name leads.
    pub end: End<'a>,
}

impl Answer<'_> {
    /// The response code: NXDOMAIN after a chain too, as the last name decides (RFC 6604 §3).
    #[must_use]
    pub const fn rcode(&self) -> Rcode {
        match self.end {
            End::NotAuth => Rcode::REFUSED,
            End::NxDomain { .. } => Rcode::NXDOMAIN,
            End::YxDomain { .. } => Rcode::YXDOMAIN,
            _ => Rcode::NOERROR,
        }
    }

    /// Whether the answer is authoritative, AA: all but a referral from the name asked, or a refusal. A chain
    /// that ends in a referral keeps it, as Knot's does.
    #[must_use]
    pub const fn authoritative(&self) -> bool {
        match self.end {
            End::NotAuth => false,
            End::Referral { .. } => !self.chain.is_empty(),
            _ => true,
        }
    }
}

/// Where a name is, in a zone that has every ancestor of its names down to the apex as a node.
enum Located<'a> {
    Exact(Entry<'a>),
    /// The closest encloser.
    Absent(Entry<'a>),
}

/// Whether `node` holds NSEC3 records and nothing else.
fn only_nsec3(node: &Node) -> bool {
    let mut sets = node.rrsets().peekable();
    sets.peek().is_some() && sets.all(|(rtype, _)| rtype == RecordType::NSEC3)
}

/// What one name leads to.
enum Step<'a> {
    End(End<'a>),
    Link(Link<'a>, Name<'a>),
}

impl Zone {
    /// What the zone answers to `question` (RFC 1034 §4.3.2; RFC 4592 §3 wildcards; RFC 6672 §3 DNAME), without
    /// DNSSEC records: those are added to the answer by the signed zone's own step (D206).
    ///
    /// Nothing of the zone is copied: the answer refers to it.
    #[must_use]
    pub fn answer<'a>(&'a self, question: &'a Question<'a>) -> Answer<'a> {
        let mut chain = Vec::new();
        if question.qclass != self.class && question.qclass != Class::ANY {
            return Answer {
                chain,
                end: End::NotAuth,
            };
        }
        let mut name = question.name.reborrow();
        let end = loop {
            if !name.is_within(&self.apex) {
                break if chain.is_empty() {
                    End::NotAuth
                } else {
                    End::Open { name }
                };
            }
            match self.step(name, question.qtype) {
                Step::End(end) => break end,
                Step::Link(link, next) => {
                    // A name met twice: the chain is a loop, which the answer shows once (RFC 1034 §3.6.2).
                    if chain.len() >= MAX_CHAIN
                        || chain.iter().any(|seen| seen.name() == link.name())
                    {
                        break End::Open {
                            name: link.name().clone(),
                        };
                    }
                    let synthesised = matches!(link, Link::Dname { .. });
                    chain.push(link);
                    if synthesised && question.qtype == RecordType::CNAME {
                        break End::Synthesized;
                    }
                    name = next;
                }
            }
        };
        Answer { chain, end }
    }

    /// Where `name`, which is within the zone, is: its node, or its closest encloser.
    fn locate<'a>(&'a self, name: &Name<'_>) -> Option<Located<'a>> {
        let mut buf = [0; MAX_NAME_LEN];
        let wire = name.to_wire(&mut buf);
        let mut at = 0;
        // The name, then each ancestor down to the apex: one of them is a node.
        loop {
            let suffix = Name::from_uncompressed(wire.get(at..)?).ok()?;
            // A name that holds nothing but NSEC3 records is no name to ask for: it is in the zone for the
            // proofs only (RFC 5155 §7.2), and Knot and NSD answer as if it were absent.
            if let Some((name, node)) = self.find(&suffix).filter(|(_, node)| !only_nsec3(node)) {
                let entry = Entry { name, node };
                return Some(if at == 0 {
                    Located::Exact(entry)
                } else {
                    Located::Absent(entry)
                });
            }
            at += usize::from(*wire.get(at)?) + 1;
        }
    }

    /// The nearest ancestor of `entry` that is not occluded: the delegation point or DNAME owner that hides it.
    fn above<'a>(&'a self, entry: Entry<'a>) -> Option<Entry<'a>> {
        let mut buf = [0; MAX_NAME_LEN];
        let wire = entry.name.to_wire(&mut buf);
        let mut at = 0;
        loop {
            at += usize::from(*wire.get(at)?) + 1;
            let suffix = Name::from_uncompressed(wire.get(at..)?).ok()?;
            let (name, node) = self.find(&suffix)?;
            if node.kind() != Kind::Occluded {
                return Some(Entry { name, node });
            }
        }
    }

    /// The wildcard that answers for a name whose closest encloser is `encloser`.
    fn wildcard<'a>(&'a self, encloser: &Name<'_>) -> Option<Entry<'a>> {
        let mut buf = [0; MAX_NAME_LEN];
        let wire = encloser.to_wire(&mut buf);
        let mut star = [0; MAX_NAME_LEN];
        let len = wire.len() + 2;
        let star = star.get_mut(..len)?;
        star.get_mut(..2)?.copy_from_slice(b"\x01*");
        star.get_mut(2..)?.copy_from_slice(wire);
        let (name, node) = self.find(&Name::from_uncompressed(star).ok()?)?;
        Some(Entry { name, node })
    }

    /// What `name`, within the zone, leads to when `qtype` is asked, .
    fn step<'a>(&'a self, name: Name<'a>, qtype: RecordType) -> Step<'a> {
        let Some(located) = self.locate(&name) else {
            // The apex is a node of every zone, so this is out of reach; refusing is the safe answer.
            return Step::End(End::NotAuth);
        };
        let at = match located {
            Located::Exact(entry) => match entry.node.kind() {
                Kind::Authoritative => Match::Exact(entry),
                Kind::Delegation if qtype == RecordType::DS => Match::Exact(entry),
                Kind::Delegation => return Step::End(End::Referral { cut: entry }),
                Kind::EmptyNonTerminal => {
                    return Step::End(End::NoData {
                        name,
                        at: Match::Exact(entry),
                    });
                }
                Kind::Occluded => return self.hidden(name, entry),
            },
            Located::Absent(encloser) => match encloser.node.kind() {
                Kind::Occluded => return self.hidden(name, encloser),
                Kind::Delegation => return Step::End(End::Referral { cut: encloser }),
                Kind::Authoritative | Kind::EmptyNonTerminal => {
                    if encloser.node.is_dname_owner() {
                        return Self::dname(name, encloser);
                    }
                    match self.wildcard(encloser.name) {
                        Some(source) => Match::Wildcard { source, encloser },
                        None => return Step::End(End::NxDomain { name, encloser }),
                    }
                }
            },
        };
        Self::at(name, at, qtype)
    }

    /// What a name hidden below a delegation point or a DNAME leads to.
    fn hidden<'a>(&'a self, name: Name<'a>, entry: Entry<'a>) -> Step<'a> {
        match self.above(entry) {
            Some(cut) if cut.node.kind() == Kind::Delegation => Step::End(End::Referral { cut }),
            // `above` finds a node that is no occluded one: a delegation point or a DNAME owner.
            Some(owner) => Self::dname(name, owner),
            None => Step::End(End::NotAuth),
        }
    }

    /// The synthesis of the DNAME of `owner` for `name` below it (RFC 6672 §3.1).
    fn dname<'a>(name: Name<'a>, owner: Entry<'a>) -> Step<'a> {
        let Some(rrset) = owner.node.rrset(RecordType::DNAME) else {
            return Step::End(End::NotAuth);
        };
        let target = rrset
            .rdatas()
            .first()
            .and_then(|rdata| match rdata.wire() {
                Cow::Borrowed(wire) => Name::from_uncompressed(wire).ok(),
                Cow::Owned(_) => None,
            })
            .and_then(|target| {
                let above = name.label_count().checked_sub(owner.name.label_count())?;
                Name::from_labels(name.labels().take(above).chain(target.labels())).ok()
            });
        match target {
            Some(target) => Step::Link(
                Link::Dname {
                    name,
                    at: owner,
                    rrset,
                    target: target.clone(),
                },
                target,
            ),
            None => Step::End(End::YxDomain {
                name,
                at: owner,
                rrset,
            }),
        }
    }

    /// What the node `at` holds for `qtype`: an alias to follow, the `RRset`, or nothing.
    fn at<'a>(name: Name<'a>, at: Match<'a>, qtype: RecordType) -> Step<'a> {
        let node = at.node();
        if let Some(rrset) = node.rrset(RecordType::CNAME)
            && !matches!(
                qtype,
                RecordType::CNAME | RecordType::RRSIG | RecordType::NSEC | RecordType::ANY
            )
        {
            let Some(target) = rrset.rdatas().first().and_then(|rdata| match rdata.wire() {
                Cow::Borrowed(wire) => Name::from_uncompressed(wire).ok(),
                Cow::Owned(_) => None,
            }) else {
                return Step::End(End::NoData { name, at });
            };
            return Step::Link(Link::Cname { name, at, rrset }, target);
        }
        // NSEC3 records are the proofs' own: never data (RFC 5155 §7.2).
        let mut sets = node
            .rrsets()
            .filter(|(rtype, _)| *rtype != RecordType::NSEC3);
        let found = match qtype {
            RecordType::ANY => sets.next(),
            RecordType::RRSIG => {
                sets.find_map(|(rtype, _)| node.signatures(rtype).map(|s| (RecordType::RRSIG, s)))
            }
            RecordType::NSEC3 => None,
            _ => node.rrset(qtype).map(|s| (qtype, s)),
        };
        Step::End(match found {
            Some((rtype, rrset)) => End::Data {
                name,
                at,
                rtype,
                rrset,
            },
            None => End::NoData { name, at },
        })
    }
}
