//! Shared proptest strategies and helpers of the integration tests.

#![allow(dead_code, reason = "each test crate uses a subset")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dedens_proto::edns::{
    ClientSubnet, Cookie, Edns, EdnsOption, ExtendedError, InfoCode, OptionCode,
};
use dedens_proto::rdata::{
    Caa, CharacterString, Mx, Opaque, Soa, Srv, SvcParam, SvcParamKey, SvcParams, Svcb, Txt,
};
use dedens_proto::wire::{Reader, Writer};
use dedens_proto::{
    Class, Counts, DecodeError, Decoded, DecodedRecord, Flags, Header, Message, Name, Opcode,
    Question, RData, Rcode, Record, RecordType, Ttl,
};
use proptest::prelude::*;

/// A name of up to 5 labels of 1 to 20 arbitrary bytes.
pub(crate) fn name() -> impl Strategy<Value = Name> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=20), 0..=5).prop_map(|labels| {
        Name::from_labels(labels.iter().map(Vec::as_slice)).expect("labels are within the limits")
    })
}

pub(crate) fn flags() -> impl Strategy<Value = Flags> {
    any::<u16>().prop_map(Flags::from_word)
}

pub(crate) fn header() -> impl Strategy<Value = Header> {
    (any::<u16>(), flags(), 0u8..16, 0u16..16).prop_map(|(id, flags, opcode, rcode)| Header {
        id,
        flags,
        opcode: Opcode(opcode),
        rcode: Rcode(rcode),
    })
}

pub(crate) fn counts() -> impl Strategy<Value = Counts> {
    any::<[u16; 4]>().prop_map(|[questions, answers, authority, additional]| Counts {
        questions,
        answers,
        authority,
        additional,
    })
}

pub(crate) fn question() -> impl Strategy<Value = Question> {
    (name(), any::<u16>(), any::<u16>()).prop_map(|(name, qtype, qclass)| Question {
        name,
        qtype: RecordType(qtype),
        qclass: Class(qclass),
    })
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max)
}

fn ipv4() -> impl Strategy<Value = Ipv4Addr> {
    any::<[u8; 4]>().prop_map(Ipv4Addr::from)
}

fn ipv6() -> impl Strategy<Value = Ipv6Addr> {
    any::<[u8; 16]>().prop_map(Ipv6Addr::from)
}

fn soa() -> impl Strategy<Value = Soa> {
    (name(), name(), any::<[u32; 5]>()).prop_map(
        |(mname, rname, [serial, refresh, retry, expire, minimum])| Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        },
    )
}

fn txt() -> impl Strategy<Value = Txt> {
    prop::collection::vec(bytes(40), 1..=4).prop_map(|strings| {
        let strings = strings
            .iter()
            .map(|s| CharacterString::new(s).expect("at most 40 bytes"))
            .collect();
        Txt::new(strings).expect("at least one string")
    })
}

fn caa() -> impl Strategy<Value = Caa> {
    (any::<u8>(), "[a-zA-Z0-9]{1,15}", bytes(30))
        .prop_map(|(flags, tag, value)| Caa::new(flags, tag.as_bytes(), &value).expect("valid tag"))
}

/// The optional parameters of a SVCB record, each present or not, so that keys never repeat.
fn svc_params() -> impl Strategy<Value = SvcParams> {
    let alpn = prop::option::of(prop::collection::vec(
        prop::collection::vec(any::<u8>(), 1..=8).prop_map(Vec::into_boxed_slice),
        1..=3,
    ));
    let v4 = prop::option::of(prop::collection::vec(ipv4(), 1..=3));
    let v6 = prop::option::of(prop::collection::vec(ipv6(), 1..=3));
    let others = (
        any::<bool>(),
        prop::option::of(any::<u16>()),
        prop::option::of(bytes(20)),
        prop::option::of("[a-z/{?}]{0,20}"),
        prop::option::of((8u16..65535, bytes(10))),
        prop::collection::vec(any::<bool>(), 8),
    );
    (alpn, v4, v6, others).prop_map(
        |(alpn, v4, v6, (no_default, port, ech, doh, unknown, listed))| {
            let mut params: Vec<SvcParam> = Vec::new();
            params.extend(alpn.map(SvcParam::Alpn));
            params.extend(no_default.then_some(SvcParam::NoDefaultAlpn));
            params.extend(port.map(SvcParam::Port));
            params.extend(v4.map(SvcParam::Ipv4Hint));
            params.extend(ech.map(|c| SvcParam::Ech(c.into())));
            params.extend(v6.map(SvcParam::Ipv6Hint));
            params.extend(doh.map(SvcParam::DohPath));
            params.extend(unknown.map(|(key, value)| SvcParam::Unknown {
                key: SvcParamKey(key),
                value: value.into(),
            }));
            let mandatory: Vec<SvcParamKey> = params
                .iter()
                .zip(listed)
                .filter_map(|(p, listed)| listed.then_some(p.key()))
                .collect();
            if !mandatory.is_empty() {
                params.push(SvcParam::Mandatory(mandatory));
            }
            SvcParams::new(params).expect("generated parameters are valid")
        },
    )
}

fn svcb() -> impl Strategy<Value = Svcb> {
    (any::<u16>(), name(), svc_params()).prop_map(|(priority, target, params)| Svcb {
        priority,
        target,
        params,
    })
}

/// RDATA of every supported type, and of unknown ones.
pub(crate) fn rdata() -> impl Strategy<Value = RData> {
    prop_oneof![
        ipv4().prop_map(RData::A),
        ipv6().prop_map(RData::Aaaa),
        name().prop_map(RData::Ns),
        name().prop_map(RData::Cname),
        name().prop_map(RData::Ptr),
        soa().prop_map(RData::Soa),
        (any::<u16>(), name()).prop_map(|(preference, exchange)| RData::Mx(Mx {
            preference,
            exchange
        })),
        txt().prop_map(RData::Txt),
        (any::<[u16; 3]>(), name()).prop_map(|([priority, weight, port], target)| RData::Srv(
            Srv {
                priority,
                weight,
                port,
                target
            }
        )),
        caa().prop_map(RData::Caa),
        svcb().prop_map(RData::Svcb),
        svcb().prop_map(RData::Https),
        (300u16..60000, bytes(40)).prop_map(|(rtype, data)| RData::Opaque(Opaque {
            rtype: RecordType(rtype),
            data: data.into()
        })),
    ]
}

pub(crate) fn record() -> impl Strategy<Value = Record> {
    (name(), any::<u16>(), 0..=Ttl::MAX.get(), rdata()).prop_map(|(name, class, ttl, data)| {
        Record::new(name, Class(class), Ttl::new(ttl).expect("in range"), data)
    })
}

fn client_subnet() -> impl Strategy<Value = ClientSubnet> {
    let v4 = (any::<u32>(), 0u8..=32, 0u8..=32).prop_map(|(addr, source, scope)| {
        let mask = u32::MAX.checked_shl(32 - u32::from(source)).unwrap_or(0);
        (IpAddr::from(Ipv4Addr::from(addr & mask)), source, scope)
    });
    let v6 = (any::<u128>(), 0u8..=128, 0u8..=128).prop_map(|(addr, source, scope)| {
        let mask = u128::MAX.checked_shl(128 - u32::from(source)).unwrap_or(0);
        (IpAddr::from(Ipv6Addr::from(addr & mask)), source, scope)
    });
    prop_oneof![v4, v6].prop_map(|(addr, source, scope)| {
        ClientSubnet::new(addr, source, scope).expect("masked address")
    })
}

pub(crate) fn edns_option() -> impl Strategy<Value = EdnsOption> {
    prop_oneof![
        bytes(20).prop_map(|b| EdnsOption::Nsid(b.into())),
        client_subnet().prop_map(EdnsOption::ClientSubnet),
        (
            any::<[u8; 8]>(),
            prop::option::of(prop::collection::vec(any::<u8>(), 8..=32))
        )
            .prop_map(|(client, server)| EdnsOption::Cookie(
                Cookie::new(client, server.as_deref()).expect("8 to 32 bytes")
            )),
        prop::option::of(any::<u16>()).prop_map(EdnsOption::Keepalive),
        (0u16..60).prop_map(EdnsOption::Padding),
        (any::<u16>(), ".{0,20}").prop_map(|(code, text)| EdnsOption::Ede(ExtendedError {
            code: InfoCode(code),
            text
        })),
        (100u16..60000, bytes(20)).prop_map(|(code, data)| EdnsOption::Unknown {
            code: OptionCode(code),
            data: data.into()
        }),
    ]
}

pub(crate) fn edns() -> impl Strategy<Value = Edns> {
    (
        any::<u16>(),
        any::<u8>(),
        any::<u8>(),
        any::<bool>(),
        0u16..0x8000,
        prop::collection::vec(edns_option(), 0..=3),
    )
        .prop_map(
            |(udp_payload, ext_rcode, version, dnssec_ok, z, options)| Edns {
                udp_payload,
                ext_rcode,
                version,
                dnssec_ok,
                z,
                options,
            },
        )
}

pub(crate) fn message() -> impl Strategy<Value = Message> {
    let records = || prop::collection::vec(record(), 0..=3);
    (
        header(),
        prop::collection::vec(question(), 0..=2),
        records(),
        records(),
        records(),
        prop::option::of(edns()),
    )
        .prop_map(
            |(header, questions, answer, authority, additional, edns)| Message {
                header,
                questions,
                answer,
                authority,
                additional,
                edns,
            },
        )
}

/// A name from labels given without the root.
pub(crate) fn name_of(labels: &[&[u8]]) -> Name {
    Name::from_labels(labels.iter().copied()).expect("labels are within the limits")
}

/// Encodes with `f` into a buffer of the maximum size and returns the bytes.
pub(crate) fn encode_with<E: std::fmt::Debug>(
    f: impl FnOnce(&mut Writer<'_>) -> Result<(), E>,
) -> Vec<u8> {
    let mut buf = vec![0; dedens_proto::wire::MAX_MESSAGE_LEN];
    let mut w = Writer::new(&mut buf);
    f(&mut w).expect("fits in 65535 bytes");
    w.written().to_vec()
}

/// A record at the root, class IN, TTL 0, of `rtype` holding `rdata` as is.
pub(crate) fn record_wire(rtype: RecordType, rdata: &[u8]) -> Vec<u8> {
    let mut wire = vec![0];
    wire.extend_from_slice(&rtype.0.to_be_bytes());
    wire.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    wire.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("short RDATA")
            .to_be_bytes(),
    );
    wire.extend_from_slice(rdata);
    wire
}

/// Decodes the whole of `wire` as one record.
pub(crate) fn decode_record(wire: &[u8]) -> Result<DecodedRecord, DecodeError> {
    Record::decode(&mut Reader::new(wire))
}

/// A message with no question and one OPT record (payload 1232, no flags) whose RDATA is `options`.
pub(crate) fn opt_message(options: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x12, 0x34, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    wire.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0]);
    wire.extend_from_slice(
        &u16::try_from(options.len())
            .expect("short options")
            .to_be_bytes(),
    );
    wire.extend_from_slice(options);
    wire
}

/// One EDNS option on the wire: code, length, data.
pub(crate) fn option_wire(code: u16, data: &[u8]) -> Vec<u8> {
    let mut wire = code.to_be_bytes().to_vec();
    wire.extend_from_slice(&u16::try_from(data.len()).expect("short data").to_be_bytes());
    wire.extend_from_slice(data);
    wire
}

/// Decodes a message made by [`opt_message`] and returns it with its violations.
pub(crate) fn decode_options(options: &[u8]) -> Decoded {
    Message::decode(&opt_message(options)).expect("well-framed message")
}

/// A reader over the whole of `bytes`.
pub(crate) fn reader(bytes: &[u8]) -> Reader<'_> {
    Reader::new(bytes)
}
