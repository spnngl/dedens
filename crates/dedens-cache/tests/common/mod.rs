//! Builders shared by the cache tests.

#![allow(dead_code, reason = "each test file uses part of the helpers")]

use std::net::Ipv4Addr;

use dedens_cache::{Cache, Config, Key, Lookup, NotCached, StalePolicy};
use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::rdata::{RData, Soa};
use dedens_proto::{Class, Flags, Message, Name, Query, Question, Rcode, Record, RecordType, Ttl};

/// Seconds at which the tests store responses.
pub(crate) const T0: u32 = 1_000;

pub(crate) fn dns(text: &str) -> Name<'static> {
    Name::from_labels(text.split('.').filter(|l| !l.is_empty()).map(str::as_bytes))
        .expect("a valid name")
}

pub(crate) fn a(owner: &str, ttl: u32, last: u8) -> Record<'static> {
    record(owner, ttl, &RData::A(Ipv4Addr::new(192, 0, 2, last)))
}

pub(crate) fn soa(owner: &str, ttl: u32, minimum: u32) -> Record<'static> {
    record(
        owner,
        ttl,
        &RData::Soa(Soa {
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

pub(crate) fn record(owner: &str, ttl: u32, data: &RData<'_>) -> Record<'static> {
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

/// A query for `qname`/`qtype`, RD set, without EDNS.
pub(crate) fn query_plain(id: u16, qname: &str, qtype: RecordType) -> Vec<u8> {
    let mut message = Message::query(id, Question::new(dns(qname), qtype));
    message.edns = None;
    message.to_vec().expect("a query fits")
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

/// Stores `response`, the answer to `query`, as a forwarder does once it has decoded it.
pub(crate) fn insert(
    cache: &Cache,
    query: &[u8],
    response: &[u8],
    now: u32,
) -> Result<(), NotCached> {
    cache.insert(
        &Query::read(query).expect("a valid query"),
        &Message::decode(response).expect("a response that decodes"),
        now,
        0,
    )
}

/// A megabyte in four shards, without a minimum TTL: the tests count seconds below its default; those of `min_ttl`
/// set it.
pub(crate) fn small_config() -> Config {
    Config {
        capacity: 1 << 20,
        shards: 4,
        min_ttl: 0,
        ..Config::default()
    }
}

pub(crate) fn small_cache() -> Cache {
    Cache::new(small_config()).expect("a valid config")
}

/// [`small_config`] with `min_ttl`.
pub(crate) fn min_cache(min_ttl: u32) -> Cache {
    Cache::new(Config {
        min_ttl,
        ..small_config()
    })
    .expect("a valid config")
}

/// A response captured from a real server, in `crates/dedens-proto/tests/testdata`.
pub(crate) fn captured(case: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../dedens-proto/tests/testdata/{case}.bin",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("a captured response")
}

/// The query a captured response answers: its question, RD set, EDNS without DO.
pub(crate) fn query_of(response: &[u8]) -> Vec<u8> {
    let question = Message::decode(response)
        .expect("a captured response decodes")
        .message
        .questions
        .swap_remove(0)
        .into_owned();
    Message::query(1, question).to_vec().expect("a query fits")
}

/// `response` with TTL `ttl` on the records of the section `pick` gives, `pick` leaving the others as captured.
pub(crate) fn retimed(
    response: &[u8],
    ttl: u32,
    pick: impl for<'a> Fn(&'a mut Message<'static>) -> &'a mut Vec<Record<'static>>,
) -> Vec<u8> {
    let mut message = Message::decode(response)
        .expect("a captured response decodes")
        .message
        .into_owned();
    for record in pick(&mut message) {
        record.ttl = Ttl::new(ttl).expect("a TTL under 2^31");
    }
    message.to_vec().expect("a response fits")
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
