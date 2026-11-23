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

    /// Whether the answer is authoritative, AA: all but a referral from the name asked, or a refusal. AA is the
    /// first owner's, so a chain that ends in a referral keeps it (RFC 6604 §2.1; Knot does the same).
    #[must_use]
    pub const fn authoritative(&self) -> bool {
        match self.end {
            End::NotAuth => false,
            End::Referral { .. } => !self.chain.is_empty(),
            _ => true,
        }
    }
}

/// Where a name is, in a zone that has every ancestor of its names down to the apex as a node (D204).
enum Located<'a> {
    /// The zone has the name, and nothing hides it.
    Exact(Entry<'a>),
    /// The zone has no such name: its closest encloser, a node that is neither a cut nor occluded.
    Absent(Entry<'a>),
    /// The name is below this delegation point or DNAME owner, the outermost: it is hidden by it, whatever the
    /// zone holds there (RFC 1034 §4.2.1, RFC 6672 §2.4).
    Cut(Entry<'a>),
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

    /// The node at `at` in the nodes, with its name.
    fn entry(&self, at: usize) -> Option<Entry<'_>> {
        self.nodes.get(at).map(|(name, node)| Entry { name, node })
    }

    /// Where `name`, which is within the zone, is: one bisection for a name the zone has, at most two for one it
    /// lacks, and no walk, whatever the depth of the name or of the zone, which a client picks. The wildcard of an
    /// absent name is one more, in [`Zone::step`].
    ///
    /// A name the zone has is hidden when it is `Kind::Occluded`, whose `cut` is the node to refer to. For one
    /// it lacks, the lookup ends where the name would sort, and its closest encloser is the ancestor it shares
    /// the most labels with the node before: that node's subtree holds every name between the encloser and the
    /// name, and every ancestor of a node is a node (D204). The encloser's own `Kind` says whether a cut is
    /// above the name.
    ///
    /// A proof-only node is no name and no encloser (RFC 5155 §7.2.8, [`Node::is_proof_only`]): asked for, it
    /// is absent; as the encloser of a name below it, its parent takes its place, at the cost of no more
    /// bisection when the parent is the apex, and one more otherwise.
    fn locate<'a>(&'a self, name: &Name<'_>) -> Option<Located<'a>> {
        let at = match self.nodes.binary_search_by(|(key, _)| key.cmp(name)) {
            Ok(at) => {
                let entry = self.entry(at)?;
                // The server acts as if the owner of an NSEC3 record did not exist (RFC 5155 §7.2.8), as Knot
                // and NSD do for the name itself.
                if !entry.node.is_proof_only() {
                    return match entry.node.kind() {
                        Kind::Occluded { cut } => self.entry(cut).map(Located::Cut),
                        _ => Some(Located::Exact(entry)),
                    };
                }
                at
            }
            Err(at) => at,
        };
        let previous = self.entry(at.checked_sub(1)?)?;
        let mut shared = previous.name.shared_labels(name);
        if shared == previous.name.label_count() && previous.node.is_proof_only() {
            // Nothing is below it but the name, which is absent: its parent, which has it as a child so is not
            // proof-only, is the closest encloser (RFC 5155 §7.2.8). The apex holds the SOA, so is never
            // proof-only and the count does not underflow.
            shared = shared.saturating_sub(1);
        }
        let encloser = if shared == previous.name.label_count() {
            previous
        } else if shared == self.apex.label_count() {
            // The usual one for a name a client invents: the apex, the first node.
            self.entry(0)?
        } else {
            // The ancestor of `name` of `shared` labels: the name's last ones, cut from its wire bytes. It sorts
            // before the node before `name`, which it is the ancestor of.
            let mut buf = [0; MAX_NAME_LEN];
            let wire = name.to_wire(&mut buf);
            let mut from = 0;
            for _ in shared..name.label_count() {
                from += usize::from(*wire.get(from)?) + 1;
            }
            let ancestor = Name::from_uncompressed(wire.get(from..)?).ok()?;
            let (name, node) = crate::zone::find(self.nodes.get(..at)?, &ancestor)?;
            Entry { name, node }
        };
        Some(match encloser.node.kind() {
            Kind::Occluded { cut } => Located::Cut(self.entry(cut)?),
            Kind::Delegation => Located::Cut(encloser),
            _ if encloser.node.is_dname_owner() => Located::Cut(encloser),
            _ => Located::Absent(encloser),
        })
    }

    /// The node of `host` whose addresses an answer may carry (D206): an authoritative one, a delegation point, or
    /// one below a delegation point, whose addresses are glue (RFC 9499) and which Knot gives as optional
    /// additional data too. Not one below a DNAME owner, which the zone's own answers redirect (RFC 6672 §2.4).
    ///
    /// One lookup: an occluded node knows its cut.
    pub(crate) fn address_node(&self, host: &Name<'_>) -> Option<&Node> {
        let node = self.node(host)?;
        match node.kind() {
            Kind::Authoritative | Kind::Delegation => Some(node),
            Kind::Occluded { cut } => self
                .nodes
                .get(cut)
                .filter(|(_, cut)| cut.kind() == Kind::Delegation)
                .map(|_| node),
            Kind::EmptyNonTerminal => None,
        }
    }

    /// The wildcard that answers for a name whose closest encloser is `encloser`: not a proof-only node, which is
    /// no name (RFC 5155 §7.2.8).
    fn wildcard<'a>(&'a self, encloser: &Name<'_>) -> Option<Entry<'a>> {
        let mut buf = [0; MAX_NAME_LEN];
        let wire = encloser.to_wire(&mut buf);
        let mut star = [0; MAX_NAME_LEN];
        let len = wire.len() + 2;
        let star = star.get_mut(..len)?;
        star.get_mut(..2)?.copy_from_slice(b"\x01*");
        star.get_mut(2..)?.copy_from_slice(wire);
        let (name, node) = self
            .find(&Name::from_uncompressed(star).ok()?)
            .filter(|(_, node)| !node.is_proof_only())?;
        Some(Entry { name, node })
    }

    /// What `name`, within the zone, leads to when `qtype` is asked: at most three bisections of `name`, two in
    /// [`Zone::locate`] and one for the wildcard.
    fn step<'a>(&'a self, name: Name<'a>, qtype: RecordType) -> Step<'a> {
        let at = match self.locate(&name) {
            Some(Located::Cut(cut)) if cut.node.kind() == Kind::Delegation => {
                return Step::End(End::Referral { cut });
            }
            Some(Located::Cut(owner)) => return Self::dname(name, owner),
            Some(Located::Exact(entry)) => match entry.node.kind() {
                Kind::Authoritative => Match::Exact(entry),
                Kind::Delegation if qtype == RecordType::DS => Match::Exact(entry),
                Kind::Delegation => return Step::End(End::Referral { cut: entry }),
                Kind::EmptyNonTerminal => {
                    return Step::End(End::NoData {
                        name,
                        at: Match::Exact(entry),
                    });
                }
                // `locate` gives a name below a cut as `Cut`.
                Kind::Occluded { .. } => return Step::End(End::NotAuth),
            },
            Some(Located::Absent(encloser)) => match self.wildcard(encloser.name) {
                // A wildcard that is a delegation point refers, as Knot's does; RFC 4592 §4.2 leaves it open. Its
                // DS is data, as at any delegation point.
                Some(source)
                    if source.node.kind() == Kind::Delegation && qtype != RecordType::DS =>
                {
                    return Step::End(End::Referral { cut: source });
                }
                Some(source) => Match::Wildcard { source, encloser },
                None => return Step::End(End::NxDomain { name, encloser }),
            },
            // `locate` gives `None` for a name before the apex, which is within the zone so never, and for an
            // ancestor it does not find, which every ancestor of a node being a node (D204) rules out. Refusing
            // is the safe answer.
            None => return Step::End(End::NotAuth),
        };
        Self::at(name, at, qtype)
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
