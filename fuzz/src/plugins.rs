//! Targets of dedens-plugins: hosts files, blocklists and allowlists from text, the blocklist against a model of
//! its two sets (D110) and its review of CNAME chains (D118).

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use dedens_cache::{Cache, Config};
use dedens_plugins::{
    Action, Blocklist, Hosts, List, Lists, MAX_HOPS, Merged, Names, Origin, Tlds,
};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, Flags, Header, MAX_MESSAGE_LEN, Message, Name, Query, Question, Rcode, Record,
    RecordType, Transport, Ttl,
};
use dedens_server::{Forward, Pipeline, Plugin, Stage, Step};

/// Arbitrary text as a hosts file, as a downloaded blocklist, and its odd lines as an allowlist: when the hosts
/// file and the blocklist read, queries for its words get replies that decode, whatever the plugins answer.
///
/// # Panics
///
/// On a bug in the readers or in the replies of plugins.
pub fn parse_lists(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    blocklist_model(text);
    blocklist_review(text);
    names_read_once(text);
    let mut lists = Lists::new();
    let (Ok(hosts), Ok(_)) = (
        Hosts::new(text, Ttl::ZERO, false),
        lists.read(List::Block, Origin::Downloaded, text),
    ) else {
        return;
    };
    let allowed: String = text
        .lines()
        .skip(1)
        .step_by(2)
        .flat_map(|line| [line, "\n"])
        .collect();
    // Refused or not, the blocklist answers as before.
    let _ = lists.read(List::Allow, Origin::Downloaded, &allowed);
    let pipeline = Pipeline::new(vec![
        Stage::Plugin(Box::new(Blocklist::new(lists, Action::Null, Ttl::ZERO))),
        Stage::Plugin(Box::new(hosts)),
    ]);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    for word in text.split_ascii_whitespace().take(8) {
        let Ok(name) = word.parse::<Name<'static>>() else {
            continue;
        };
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::PTR] {
            let Ok(query) = Message::query(1, Question::new(name.clone(), qtype)).to_vec() else {
                continue;
            };
            if let Step::Reply(len) = pipeline.query(
                &query,
                Transport::Udp,
                Ipv4Addr::LOCALHOST.into(),
                0,
                &mut out,
            ) && let Err(error) = Message::decode(&out[..len])
            {
                panic!("{word} {qtype}: the reply does not decode: {error}");
            }
        }
    }
}

/// A downloaded text read once as [`Names`], whole or in two halves, and merged, is what [`Lists::read`] makes of
/// the text, whole or one half after the other, under either setting of top-level domains (D120): the same
/// refusals, counts and set size.
fn names_read_once(text: &str) {
    let lines = text.split_inclusive('\n');
    let cut: usize = lines.clone().take(lines.count() / 2).map(str::len).sum();
    let (head, tail) = text.split_at(cut);
    for tlds in [Tlds::Refuse, Tlds::Allow] {
        let mut together = Lists::with_tlds(tlds);
        let read = together.read(List::Block, Origin::Downloaded, text);
        let names = Names::downloaded(text);
        assert_eq!(read, names.check(tlds), "whole, {tlds:?}");
        let merged = Merged::new(tlds, &[names]);
        assert_eq!(read.is_ok(), merged.is_ok(), "merged, {tlds:?}");
        if let Ok(merged) = merged {
            assert_eq!(merged.len(), together.names(List::Block), "{tlds:?}");
            assert_eq!(merged.duplicates(), together.duplicates(List::Block));
        }
        let mut apart = Lists::with_tlds(tlds);
        let both =
            [head, tail].map(|half| apart.read(List::Block, Origin::Downloaded, half).is_ok());
        let merged = Merged::new(tlds, &[Names::downloaded(head), Names::downloaded(tail)]);
        assert_eq!(both == [true, true], merged.is_ok(), "halves, {tlds:?}");
        if let Ok(merged) = merged {
            assert_eq!(merged.len(), apart.names(List::Block), "{tlds:?}");
            assert_eq!(merged.duplicates(), apart.duplicates(List::Block));
        }
    }
}

/// The words of `text` that are host names as a chain of CNAME records from the query name, the even words listed
/// (D118): the review of the response blocks it when one of the
/// first `MAX_HOPS + 1` targets is a name the plugin blocks as a query name, answers SERVFAIL when the chain goes
/// on, and lets it through otherwise; the pipeline's reply decodes, asked a second time as well when the cache
/// answers.
fn blocklist_review(text: &str) {
    let block: String = text
        .split_ascii_whitespace()
        .step_by(2)
        .flat_map(|word| [word, "\n"])
        .collect();
    let mut lists = Lists::new();
    if lists.read(List::Block, Origin::Downloaded, &block).is_err() {
        return;
    }
    let reviewing = lists.names(List::Block) > 0;
    let blocklist = Blocklist::new(lists, Action::Nxdomain, Ttl::ZERO);
    let targets: Vec<Name<'static>> = text
        .split_ascii_whitespace()
        .filter_map(|word| word.parse().ok())
        .take(MAX_HOPS + 2)
        .collect();
    if targets.is_empty() {
        return;
    }
    // The expected verdict follows the chain through distinct names only: a name twice makes a loop or a shorter
    // chain, which the reply must survive but is not modelled.
    let start: Name<'static> = "chain.test.".parse().expect("a name");
    let owners: HashSet<Vec<Vec<u8>>> = targets
        .iter()
        .chain([&start])
        .map(|name| name.labels().map(<[u8]>::to_ascii_lowercase).collect())
        .collect();
    let modelled = owners.len() == targets.len() + 1;
    let blocked = |name: &Name<'static>| {
        Message::query(1, Question::new(name.clone(), RecordType::A))
            .to_vec()
            .is_ok_and(|wire| Query::read(&wire).is_ok_and(|q| blocklist.answer(&q).is_some()))
    };
    let blocks = reviewing && targets.iter().take(MAX_HOPS + 1).any(blocked);
    let too_long = reviewing && !blocks && targets.len() > MAX_HOPS;
    let answer = targets
        .iter()
        .scan(start.clone(), |owner, target| {
            let record = Record::new(
                owner.clone(),
                Class::IN,
                Ttl::from_wire(60),
                &RData::Cname(target.clone()),
            );
            *owner = target.clone();
            Some(record)
        })
        .collect();
    let question = Question::new(start, RecordType::A);
    let Ok(query) = Message::query(1, question.clone()).to_vec() else {
        return;
    };
    let response = Message {
        header: Header {
            id: 1,
            flags: Flags::QR | Flags::RD | Flags::RA,
            ..Header::default()
        },
        questions: vec![question],
        answer,
        ..Message::default()
    };
    let Ok(wire) = response.to_vec() else {
        return;
    };
    let pipeline = Pipeline::new(vec![
        Stage::Plugin(Box::new(blocklist)),
        Stage::Cache(Arc::new(
            Cache::new(Config {
                capacity: 1 << 20,
                shards: 1,
                ..Config::default()
            })
            .expect("a valid config"),
        )),
        Stage::Forward(Forward::new([SocketAddr::from(([192, 0, 2, 53], 53))]).expect("a server")),
    ]);
    let mut out = vec![0; 1 << 13];
    let ask =
        |out: &mut [u8]| pipeline.query(&query, Transport::Udp, Ipv4Addr::LOCALHOST.into(), 0, out);
    let Step::Upstream(upstream) = ask(&mut out) else {
        return;
    };
    let Step::Reply(len) = pipeline.receive(upstream, Some(&wire), 0, &mut out) else {
        return;
    };
    let first = Message::decode(&out[..len]).map(|reply| reply.message.rcode());
    let Ok(first) = first else {
        panic!("the reply does not decode: {first:?}");
    };
    if modelled {
        assert_eq!(first == Rcode::NXDOMAIN, blocks, "{targets:?}");
        assert_eq!(first == Rcode::SERVFAIL, too_long, "{targets:?}");
    }
    // Asked again: from the cache when the response was kept, as the first time said.
    if let Step::Reply(len) = ask(&mut out) {
        let again = Message::decode(&out[..len]).map(|reply| reply.message.rcode());
        assert!(again.is_ok(), "the cached reply does not decode: {again:?}");
        if modelled && let Ok(again) = again {
            assert_eq!(again == Rcode::NXDOMAIN, blocks, "{targets:?}");
        }
    }
}

/// The first words of `text` as host names, of a blocklist and of an allowlist alternately: a query is blocked
/// exactly when a suffix of its name is blocked and none is allowed, whatever the case, as a plain model of the
/// two sets says (D110). The queries are the listed names, their suffixes, and a name below each in other case.
fn blocklist_model(text: &str) {
    type Labels = Vec<Vec<u8>>;
    let mut lists = Lists::new();
    let (mut block, mut allow) = (HashSet::<Labels>::new(), HashSet::<Labels>::new());
    let mut names = Vec::new();
    // Words the line reader takes whole: no other whitespace, comment or byte order mark.
    let plain = |word: &&str| {
        word.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.*:".contains(&byte))
    };
    for (index, word) in text
        .split_ascii_whitespace()
        .filter(plain)
        .take(16)
        .enumerate()
    {
        let (list, held) = if index % 2 == 0 {
            (List::Block, &mut block)
        } else {
            (List::Allow, &mut allow)
        };
        let Ok(read) = lists.read(list, Origin::Local, word) else {
            continue;
        };
        // An address is no name; `*.` reads as the name after it.
        if read.names + read.duplicates == 0 {
            continue;
        }
        let Ok(name) = word
            .strip_prefix("*.")
            .unwrap_or(word)
            .parse::<Name<'static>>()
        else {
            return;
        };
        held.insert(name.labels().map(<[u8]>::to_ascii_lowercase).collect());
        names.push(name);
    }
    let blocklist = Blocklist::new(lists, Action::Nxdomain, Ttl::ZERO);
    let listed = |set: &HashSet<Labels>, labels: &[Vec<u8>]| {
        (0..labels.len()).any(|at| labels.get(at..).is_some_and(|suffix| set.contains(suffix)))
    };
    for name in names {
        let labels: Labels = name.labels().map(<[u8]>::to_vec).collect();
        let mut queries: Vec<Labels> = (0..labels.len())
            .filter_map(|at| labels.get(at..).map(<[Vec<u8>]>::to_vec))
            .collect();
        queries.push([vec![b'x']].into_iter().chain(labels.clone()).collect());
        queries.push(
            labels
                .iter()
                .map(|label| label.to_ascii_uppercase())
                .collect(),
        );
        for labels in queries {
            let Ok(name) = Name::from_labels(labels.iter().map(Vec::as_slice)) else {
                continue;
            };
            let lower: Labels = labels
                .iter()
                .map(|label| label.to_ascii_lowercase())
                .collect();
            let expected = listed(&block, &lower) && !listed(&allow, &lower);
            let shown = name.to_string();
            let wire = Message::query(1, Question::new(name, RecordType::A))
                .to_vec()
                .expect("a query of a valid name encodes");
            let query = Query::read(&wire).expect("a query of a valid name reads");
            assert_eq!(
                blocklist.answer(&query).is_some(),
                expected,
                "{shown}: block {block:?}, allow {allow:?}"
            );
        }
    }
}
