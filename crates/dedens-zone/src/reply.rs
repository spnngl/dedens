//! The sections of a response from an [`Answer`], and its encoding (D206).

use dedens_proto::rdata::RData;
use dedens_proto::{EncodeError, Flags, Message, Name, Record, RecordType, Ttl, WireRdata};

use crate::answer::{Answer, End, Link};
use crate::{RrSet, Zone};

/// The bit of the header's flags word that is TC, in its first byte at offset 2.
const TC_BYTE: u8 = 0x02;

/// What must stay in the additional section of a response for it to be sent without TC (RFC 9471 §3.1): the
/// glue a referral cannot do without, which comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Glue {
    required: usize,
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
    /// # Errors
    ///
    /// As [`Message::encode_truncated`].
    pub fn encode(self, message: &Message<'_>, buf: &mut [u8]) -> Result<usize, EncodeError> {
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

impl Answer<'_> {
    /// Adds the records of the answer to `message`, a response whose header and question are the caller's: its
    /// answer, authority and additional sections, AA and the response code. Nothing but the synthesised CNAME of
    /// a DNAME is copied.
    ///
    /// The additional section holds the addresses of the name servers, mail exchanges and service hosts of the
    /// answer that the zone has, A before AAAA, and for a referral first those of name servers at or below the
    /// delegation point, the glue it needs (RFC 9471 §2, §3.1); a name asked for is never resolved there
    /// (RFC 2181 §10.3).
    pub fn fill<'m>(&'m self, zone: &'m Zone, message: &mut Message<'m>) -> Glue {
        let class = zone.class();
        if self.authoritative() {
            message.header.flags = message.header.flags.with(Flags::AA);
        }
        message.header.rcode = self.rcode();
        for link in &self.chain {
            match link {
                Link::Cname { name, rrset, .. } => records(&mut message.answer, name, zone, rrset),
                Link::Dname {
                    name,
                    at,
                    rrset,
                    target,
                } => {
                    records(&mut message.answer, at.name, zone, rrset);
                    message.answer.push(Record {
                        name: name.clone(),
                        class,
                        ttl: rrset.ttl(),
                        rdata: WireRdata::new(&RData::Cname(target.reborrow())),
                    });
                }
            }
        }
        let mut glue = Glue::default();
        match &self.end {
            End::Data {
                name, rtype, rrset, ..
            } => {
                records(&mut message.answer, name, zone, rrset);
                additional(zone, *rtype, rrset, None, &mut message.additional);
            }
            End::NoData { .. } | End::NxDomain { .. } => soa(zone, &mut message.authority),
            End::Referral { cut } => {
                if let Some(rrset) = cut.node.rrset(RecordType::NS) {
                    records(&mut message.authority, cut.name, zone, rrset);
                    glue.required = additional(
                        zone,
                        RecordType::NS,
                        rrset,
                        Some(cut.name),
                        &mut message.additional,
                    );
                }
            }
            End::YxDomain { at, rrset, .. } => records(&mut message.answer, at.name, zone, rrset),
            End::NotAuth | End::Synthesized | End::Open { .. } => {}
        }
        glue
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

/// Adds the SOA, with the TTL of a negative answer: the lower of its own and its MINIMUM (RFC 2308 §3, §5).
fn soa<'m>(zone: &'m Zone, out: &mut Vec<Record<'m>>) {
    if let Some(rrset) = zone.soa_rrset() {
        let ttl = rrset.ttl().min(Ttl::from_wire(zone.soa().minimum));
        out.extend(rrset.rdatas().iter().map(|rdata| Record {
            name: zone.apex().reborrow(),
            class: zone.class(),
            ttl,
            rdata: rdata.reborrow(),
        }));
    }
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

/// Adds the addresses the zone has for the hosts of `rrset`, of `rtype`; with a delegation point `cut`, those at
/// or below it come first. Returns how many records those are.
fn additional<'m>(
    zone: &'m Zone,
    rtype: RecordType,
    rrset: &'m RrSet,
    cut: Option<&Name<'_>>,
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
    for pass in passes {
        for host in rrset.rdatas().iter().filter_map(host) {
            let below = cut.is_some_and(|cut| host.is_within(cut));
            if pass.is_some_and(|wanted| wanted != below) {
                continue;
            }
            let Some(node) = zone.node(&host) else {
                continue;
            };
            for rtype in [RecordType::A, RecordType::AAAA] {
                let Some(set) = node.rrset(rtype) else {
                    continue;
                };
                if out.iter().any(|r| r.rtype() == rtype && r.name == host) {
                    continue;
                }
                let before = out.len();
                records(out, &host, zone, set);
                if *pass == Some(true) {
                    required += out.len() - before;
                }
            }
        }
    }
    required
}
