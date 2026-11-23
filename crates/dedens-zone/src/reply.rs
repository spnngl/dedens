//! The sections of a response from an [`Answer`], and its encoding (D206).

use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::rdata::RData;
use dedens_proto::{EncodeError, Flags, Message, Name, Record, RecordType, Ttl, WireRdata};

use crate::answer::{Answer, End, Entry, Link, Match};
use crate::denial::Proofs;
use crate::{Node, RrSet, Zone};

/// The bit of the header's flags word that is TC, in its first byte at offset 2.
const TC_BYTE: u8 = 0x02;

/// What must stay in the additional section of a response for it to be sent without TC (RFC 9471 §3.1): the
/// glue a referral cannot do without, which comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Glue {
    required: usize,
    /// The `limit` the sections were collected for: [`Glue::encode`] writes into no more.
    limit: usize,
}

impl Glue {
    /// How many records at the start of the additional section are required.
    #[must_use]
    pub const fn required(self) -> usize {
        self.required
    }

    /// Writes `message` into `buf` like [`Message::encode_truncated`], and sets TC too when the required glue
    /// does not fit: the answer and authority sections are never cut without it, the rest of the additional
    /// section is dropped whole `RRset`s at a time (RFC 9471 §3.1, RFC 2181 §9).
    ///
    /// `buf` must be no longer than the `limit` given to [`Answer::fill`]: it collected addresses for no more,
    /// and stopped inside the required glue when that did not fit, which only a buffer of at most `limit` bytes
    /// reports as TC. With a larger one, required glue could be cut off without TC. To send less than the buffer
    /// holds, give `fill` that size.
    ///
    /// # Errors
    ///
    /// As [`Message::encode_truncated`].
    pub fn encode(self, message: &Message<'_>, buf: &mut [u8]) -> Result<usize, EncodeError> {
        // `fill` writes the required glue first into an additional section it found empty.
        debug_assert!(self.required <= message.additional.len());
        debug_assert!(
            buf.len() <= self.limit,
            "{} bytes to write, the sections were collected for {}",
            buf.len(),
            self.limit
        );
        let encoded = message.encode_truncated(buf)?;
        let kept = message.additional.len().saturating_sub(encoded.dropped);
        if !encoded.truncated
            && kept < self.required
            && let Some(flags) = buf.get_mut(2)
        {
            *flags |= TC_BYTE;
        }
        Ok(encoded.len)
    }
}

/// Whether a response carries the DNSSEC records of the zone: the requester's DO bit (RFC 3225 §3, RFC 4035
/// §3.2.1). A server sets DO in its OPT record as the query did; the choice is passed apart, so that no response
/// is signed or left unsigned by what its OPT record happens to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dnssec {
    /// No OPT record, or DO clear: the records asked for alone.
    Without,
    /// DO set: the signatures, and the proofs of what the answer lacks.
    With,
}

impl Dnssec {
    /// The choice of a query whose OPT record is `edns`.
    #[must_use]
    pub fn asked(edns: Option<&Edns<'_>>) -> Self {
        if edns.is_some_and(|edns| edns.flags.contains(EdnsFlags::DO)) {
            Self::With
        } else {
            Self::Without
        }
    }
}

impl Answer<'_> {
    /// Adds the records of the answer to `message`, a response whose header and question are the caller's: its
    /// answer, authority and additional sections, AA and the response code. Nothing but the synthesised CNAME of
    /// a DNAME is copied.
    ///
    /// The additional section holds the addresses of the name servers, mail exchanges and service hosts of the
    /// answer that the zone has, A before AAAA, and for a referral first those of name servers at or below the
    /// delegation point, the glue it needs (RFC 9471 §2, §3.1). No alias is followed: the target of an NS or MX
    /// record must not be one (RFC 2181 §10.3). The additional section of `message` must be empty. The addresses
    /// are those of authoritative names, of delegation points and, as optional data, of the glue below one, as
    /// Knot does (the root zone's `. NS` answer has the root servers' addresses, which sit below `net.`); never
    /// those below a DNAME owner, which the zone's own answers redirect (RFC 6672 §2.4).
    ///
    /// `limit` is the most bytes the response may have, the requester's size or [`MAX_MESSAGE_LEN`]: the
    /// addresses stop being collected once they would not fit in it, whole `RRset`s at a time, so a zone of
    /// many hosts with many addresses costs no more than a response can carry (D206). The returned [`Glue`]
    /// encodes `message` into a buffer of at most `limit` bytes.
    ///
    /// With [`Dnssec::With`], the requester's DO (RFC 3225 §3), each
    /// `RRset` has its signatures right after it, but for the NS of a referral and its glue, which the zone does
    /// not sign, and the CNAME a DNAME synthesises, which no one signs (RFC 4035 §3.1.1, RFC 6672 §5.3.1). The
    /// authority section then holds the NSEC or NSEC3 records that prove what the answer lacks or a wildcard
    /// answered, with their signatures, and a referral the DS of the child or the proof that it has none
    /// (RFC 4035 §3.1.3, §3.1.4, RFC 5155 §7.2, D209). A record cut off in the answer or authority section sets
    /// TC; a signature of an address, optional, is dropped first, without TC.
    ///
    /// [`MAX_MESSAGE_LEN`]: dedens_proto::MAX_MESSAGE_LEN
    pub fn fill<'m>(
        &'m self,
        zone: &'m Zone,
        message: &mut Message<'m>,
        limit: usize,
        dnssec: Dnssec,
    ) -> Glue {
        let class = zone.class();
        if self.authoritative() {
            message.header.flags = message.header.flags.with(Flags::AA);
        }
        message.header.rcode = self.rcode();
        let out = Out {
            zone,
            dnssec: dnssec == Dnssec::With,
        };
        let mut proofs = Proofs::new();
        for link in &self.chain {
            match link {
                Link::Cname { name, at, rrset } => {
                    out.signed(
                        &mut message.answer,
                        name,
                        at.node(),
                        RecordType::CNAME,
                        rrset,
                    );
                    out.prove_wildcard(name, at, &mut proofs);
                }
                Link::Dname {
                    name,
                    at,
                    rrset,
                    target,
                } => {
                    out.signed(
                        &mut message.answer,
                        at.name,
                        at.node,
                        RecordType::DNAME,
                        rrset,
                    );
                    message.answer.push(Record {
                        name: name.clone(),
                        class,
                        ttl: rrset.ttl(),
                        rdata: WireRdata::new(&RData::Cname(target.reborrow())),
                    });
                }
            }
        }
        let mut glue = Glue { required: 0, limit };
        match &self.end {
            End::Data {
                name,
                at,
                rtype,
                rrset,
            } => {
                out.signed(&mut message.answer, name, at.node(), *rtype, rrset);
                out.prove_wildcard(name, at, &mut proofs);
                additional(out, *rtype, rrset, None, limit, &mut message.additional);
            }
            End::NoData { name, at } => {
                out.soa(&mut message.authority);
                if out.dnssec {
                    zone.prove_no_data(name, at, &mut proofs);
                }
            }
            End::NxDomain { name, encloser } => {
                out.soa(&mut message.authority);
                if out.dnssec {
                    zone.prove_no_name(name, encloser, &mut proofs);
                }
            }
            End::Referral { cut } => {
                if let Some(rrset) = cut.node.rrset(RecordType::NS) {
                    records(&mut message.authority, cut.name, zone, rrset);
                    glue.required = additional(
                        out,
                        RecordType::NS,
                        rrset,
                        Some(cut.name),
                        limit,
                        &mut message.additional,
                    );
                }
                out.ds(cut, &mut message.authority, &mut proofs);
            }
            End::YxDomain { at, rrset, .. } => {
                out.signed(
                    &mut message.answer,
                    at.name,
                    at.node,
                    RecordType::DNAME,
                    rrset,
                );
            }
            End::NotAuth | End::Synthesized | End::Open { .. } => {}
        }
        out.proofs(&proofs, &mut message.authority);
        glue
    }
}

/// Where the records of a response come from, and whether they go with their signatures: DO.
#[derive(Clone, Copy)]
struct Out<'m> {
    zone: &'m Zone,
    dnssec: bool,
}

impl<'m> Out<'m> {
    /// Adds `rrset`, of `rtype` at `node`, owned by `owner`, then under DO its signatures (RFC 4035 §3.1.1).
    fn signed(
        self,
        out: &mut Vec<Record<'m>>,
        owner: &Name<'m>,
        node: &'m Node,
        rtype: RecordType,
        rrset: &'m RrSet,
    ) {
        records(out, owner, self.zone, rrset);
        self.signatures(out, owner, node, rtype);
    }

    /// Under DO, adds the signatures of the `RRset` of `rtype` at `node`, owned by `owner`.
    fn signatures(
        self,
        out: &mut Vec<Record<'m>>,
        owner: &Name<'m>,
        node: &'m Node,
        rtype: RecordType,
    ) {
        if let (true, Some(signatures)) = (self.dnssec, node.signatures(rtype)) {
            records(out, owner, self.zone, signatures);
        }
    }

    /// Under DO, proves that `name`, answered at `at`, is absent when a wildcard answered it (RFC 4035
    /// §3.1.3.3, RFC 5155 §7.2.6).
    fn prove_wildcard(self, name: &Name<'_>, at: &Match<'m>, proofs: &mut Proofs<'m>) {
        if let (true, Match::Wildcard { encloser, .. }) = (self.dnssec, at) {
            self.zone.prove_wildcard_answer(name, encloser, proofs);
        }
    }

    /// Under DO, adds the DS of the delegation at `cut` with its signatures, or proves it has none (RFC 4035
    /// §3.1.4, RFC 5155 §7.2.7).
    fn ds(self, cut: &Entry<'m>, out: &mut Vec<Record<'m>>, proofs: &mut Proofs<'m>) {
        if !self.dnssec {
            return;
        }
        match cut.node.rrset(RecordType::DS) {
            Some(ds) => self.signed(out, cut.name, cut.node, RecordType::DS, ds),
            None => self
                .zone
                .prove_no_data(cut.name, &Match::Exact(*cut), proofs),
        }
    }

    /// Adds the SOA, with the TTL of a negative answer: the lower of its own and its MINIMUM (RFC 2308 §3, §5),
    /// then under DO its signatures with that TTL too.
    fn soa(self, out: &mut Vec<Record<'m>>) {
        let zone = self.zone;
        let Some(apex) = zone.apex_node() else {
            return;
        };
        let ttl = zone.soa_ttl().min(Ttl::from_wire(zone.soa().minimum));
        let signatures = apex.signatures(RecordType::SOA).filter(|_| self.dnssec);
        let sets = apex.rrset(RecordType::SOA).into_iter().chain(signatures);
        out.extend(sets.flat_map(RrSet::rdatas).map(|rdata| Record {
            name: zone.apex().reborrow(),
            class: zone.class(),
            ttl,
            rdata: rdata.reborrow(),
        }));
    }

    /// Adds the NSEC or NSEC3 records of `proofs`, each with its signatures.
    fn proofs(self, proofs: &[Entry<'m>], out: &mut Vec<Record<'m>>) {
        let Some(rtype) = self.zone.denial.rtype() else {
            return;
        };
        for proof in proofs {
            if let Some(rrset) = proof.node.rrset(rtype) {
                self.signed(out, proof.name, proof.node, rtype, rrset);
            }
        }
    }
}

/// Adds the records of `rrset` owned by `owner`.
fn records<'m>(out: &mut Vec<Record<'m>>, owner: &Name<'m>, zone: &Zone, rrset: &'m RrSet) {
    out.extend(rrset.rdatas().iter().map(|rdata| Record {
        name: owner.clone(),
        class: zone.class(),
        ttl: rrset.ttl(),
        rdata: rdata.reborrow(),
    }));
}

/// The host a record of `rdata` points to for whom an address is wanted: the name server, mail exchange or
/// service host.
fn host<'m>(rdata: &'m WireRdata<'_>) -> Option<Name<'m>> {
    match rdata.data() {
        RData::Ns(name) => Some(name),
        RData::Mx(mx) => Some(mx.exchange),
        RData::Srv(srv) => Some(srv.target),
        _ => None,
    }
}

/// The least a record takes on the wire: a compression pointer for the owner, the type, class, TTL and length.
const MIN_RECORD_LEN: usize = 2 + 10;

/// Adds the addresses the zone has for the hosts of `rrset`, of `rtype`; with a delegation point `cut`, those at
/// or below it come first. Returns how many records those are. Under DO the signatures of the addresses follow
/// them all, so a response short of room drops those first (RFC 4035 §3.1.1); glue has none.
///
/// Stops once the records added take over `limit` bytes at the least: what comes after would be cut off.
fn additional<'m>(
    out_of: Out<'m>,
    rtype: RecordType,
    rrset: &'m RrSet,
    cut: Option<&Name<'_>>,
    limit: usize,
    out: &mut Vec<Record<'m>>,
) -> usize {
    if !matches!(rtype, RecordType::NS | RecordType::MX | RecordType::SRV) {
        return 0;
    }
    let mut required = 0;
    // With a delegation point: the hosts below it, then the others; without, all in one pass.
    let passes: &[Option<bool>] = if cut.is_some() {
        &[Some(true), Some(false)]
    } else {
        &[None]
    };
    let zone = out_of.zone;
    let hosts: Vec<Name<'m>> = rrset.rdatas().iter().filter_map(host).collect();
    let mut signatures = Vec::new();
    let mut taken = 0;
    for pass in passes {
        for (at, host) in hosts.iter().enumerate() {
            if taken > limit {
                out.append(&mut signatures);
                return required;
            }
            let below = cut.is_some_and(|cut| host.is_within(cut));
            // A host twice in the set (two MX of one exchange) has its addresses once: quadratic in the hosts,
            // which the zone's `records_per_rrset` bounds.
            if pass.is_some_and(|wanted| wanted != below)
                || hosts.iter().take(at).any(|earlier| earlier == host)
            {
                continue;
            }
            let Some(node) = zone.address_node(host) else {
                continue;
            };
            for (rtype, rdata_len) in [(RecordType::A, 4), (RecordType::AAAA, 16)] {
                let Some(set) = node.rrset(rtype) else {
                    continue;
                };
                let before = out.len();
                records(out, host, zone, set);
                out_of.signatures(&mut signatures, host, node, rtype);
                let added = out.len() - before;
                taken += added * (MIN_RECORD_LEN + rdata_len);
                if *pass == Some(true) {
                    required += added;
                }
            }
        }
    }
    out.append(&mut signatures);
    required
}
