//! Builders shared by the cache tests.

#![allow(dead_code, reason = "each test file uses part of the helpers")]

use std::net::Ipv4Addr;

use dedens_cache::{Cache, Config, Key, Lookup, StalePolicy};
use dedens_proto::rdata::Soa;
use dedens_proto::{
    Class, Edns, EdnsFlags, Flags, Message, Name, Query, Question, RData, Rcode, Record,
    RecordType, Ttl,
};

/// Seconds at which the tests store responses.
pub(crate) const T0: u32 = 1_000;

pub(crate) fn dns(text: &str) -> Name<'static> {
    Name::from_labels(text.split('.').filter(|l| !l.is_empty()).map(str::as_bytes))
        .expect("a valid name")
}

pub(crate) fn a(owner: &str, ttl: u32, last: u8) -> Record<'static> {
    record(owner, ttl, RData::A(Ipv4Addr::new(192, 0, 2, last)))
}

pub(crate) fn soa(owner: &str, ttl: u32, minimum: u32) -> Record<'static> {
    record(
        owner,
        ttl,
        RData::Soa(Soa {
            mname: dns("ns.example"),
            rname: dns("hostmaster.example"),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum,
        }),
    )
}

pub(crate) fn record(owner: &str, ttl: u32, data: RData<'static>) -> Record<'static> {
    Record::new(
        dns(owner),
        Class::IN,
        Ttl::new(ttl).expect("a TTL under 2^31"),
        data,
    )
}

/// A query for `qname`/`qtype`, RD set, EDNS without DO.
pub(crate) fn query(id: u16, qname: &str, qtype: RecordType) -> Vec<u8> {
    Message::query(id, Question::new(dns(qname), qtype))
        .to_vec()
        .expect("a query fits")
}

/// A query with the given header flags and DO bit.
pub(crate) fn query_with(
    id: u16,
    qname: &str,
    qtype: RecordType,
    flags: Flags,
    dnssec_ok: bool,
) -> Vec<u8> {
    let mut message = Message::query(id, Question::new(dns(qname), qtype));
    message.header.flags = flags;
    let edns = Edns {
        flags: if dnssec_ok {
            EdnsFlags::DO
        } else {
            EdnsFlags::default()
        },
        ..Edns::default()
    };
    message.edns = Some(edns);
    message.to_vec().expect("a query fits")
}

/// An upstream response: QR, RD, RA, AA, ID 0x4242, EDNS.
pub(crate) fn response(
    qname: &str,
    qtype: RecordType,
    rcode: Rcode,
    answer: Vec<Record<'static>>,
    authority: Vec<Record<'static>>,
) -> Vec<u8> {
    let mut message = Message::query(0x4242, Question::new(dns(qname), qtype));
    message.header.flags = Flags::QR.with(Flags::RD).with(Flags::RA).with(Flags::AA);
    message.header.rcode = rcode;
    message.answer = answer;
    message.authority = authority;
    message.to_vec().expect("a response fits")
}

pub(crate) fn key_of(query: &[u8]) -> Key {
    Key::of(&Query::read(query).expect("a valid query")).expect("a question")
}

pub(crate) fn small_cache() -> Cache {
    Cache::new(Config {
        capacity: 1 << 20,
        shards: 4,
        ..Config::default()
    })
    .expect("a valid config")
}

/// Looks `query` up and decodes what was served.
pub(crate) fn lookup(
    cache: &Cache,
    query: &[u8],
    now: u32,
    stale: StalePolicy,
) -> (Lookup, Option<Message<'static>>) {
    let mut out = vec![0; 65_535];
    let found = cache.lookup(
        &Query::read(query).expect("a valid query"),
        now,
        stale,
        &mut out,
    );
    let message = match found {
        Lookup::Hit(hit) => Some(
            Message::decode(&out[..hit.len])
                .expect("a served response decodes")
                .message
                .into_owned(),
        ),
        _ => None,
    };
    (found, message)
}

/// TTLs of every record served.
pub(crate) fn ttls(message: &Message<'_>) -> Vec<u32> {
    message
        .answer
        .iter()
        .chain(&message.authority)
        .chain(&message.additional)
        .map(|r| r.ttl.get())
        .collect()
}
