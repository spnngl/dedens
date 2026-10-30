//! The blocklist plugin (D54, D56) on published lists: the heads of `StevenBlack/hosts`
//! (`testdata/stevenblack.hosts`), of the Multi LIGHT domains of `hagezi/dns-blocklists`
//! (`testdata/hagezi-light.txt`), of its Multi PRO in the wildcard format (`testdata/hagezi-pro-wildcard.txt`) and
//! of its referral allowlist (`testdata/hagezi-referral-allow.txt`), each with a few lines of further down. Blocked
//! answers carry the Extended DNS Error Blocked (RFC 8914 §4.16). Texts that are no lists: the head of the Multi
//! LIGHT in Adblock syntax (`testdata/hagezi-light.adblock`) and nginx's 404 page, as `dl-cdn.alpinelinux.org`
//! serves it (`testdata/nginx-404.html`).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use dedens_plugins::{Action, Blocklist, LineErrorKind, List, ListError, Lists, Origin, Read};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Class, Flags, Message, Name, Question, RData, Rcode, RecordType, Ttl};
use dedens_server::{Forward, Pipeline, Stage, Step, Transport};

const STEVENBLACK: &str = include_str!("testdata/stevenblack.hosts");
const HAGEZI: &str = include_str!("testdata/hagezi-light.txt");
const WILDCARD: &str = include_str!("testdata/hagezi-pro-wildcard.txt");
const REFERRAL: &str = include_str!("testdata/hagezi-referral-allow.txt");
const ADBLOCK: &str = include_str!("testdata/hagezi-light.adblock");
const NGINX_404: &str = include_str!("testdata/nginx-404.html");

fn lists(text: &str) -> Lists {
    let mut lists = Lists::new();
    lists
        .read(List::Block, Origin::Local, text)
        .expect("the list reads");
    lists
}

fn pipeline(text: &str, action: Action) -> Pipeline {
    with_lists(lists(text), action)
}

fn with_lists(lists: Lists, action: Action) -> Pipeline {
    let blocklist = Blocklist::new(lists, action, Ttl::from_wire(60));
    let upstream = SocketAddr::from(([192, 0, 2, 53], 53));
    Pipeline::new(vec![
        Stage::Plugin(Box::new(blocklist)),
        Stage::Forward(Forward::new([upstream]).expect("a server")),
    ])
}

/// The reply of `pipeline` to a query with EDNS for `name` and `qtype` in `class`; `None` when it goes upstream.
fn ask(
    pipeline: &Pipeline,
    name: &str,
    qtype: RecordType,
    class: Class,
) -> Option<Message<'static>> {
    let name: Name<'static> = name.parse().expect("a name");
    let mut query = Message::query(7, Question::new(name, qtype));
    query.questions[0].qclass = class;
    let query = query.to_vec().expect("a query fits");
    let mut out = vec![0; 65535];
    match pipeline.query(&query, Transport::Udp, 0, &mut out) {
        Step::Reply(len) => Some(
            Message::decode(&out[..len])
                .expect("the reply decodes")
                .message
                .into_owned(),
        ),
        Step::Upstream(_) => None,
        step => unreachable!("{step:?}"),
    }
}

fn blocked(pipeline: &Pipeline, name: &str) -> bool {
    ask(pipeline, name, RecordType::A, Class::IN).is_some()
}

/// A listed name blocks itself and its subdomains, in any case; its parents and other names go on.
#[test]
fn listed_names_and_their_subdomains_are_blocked() {
    let hosts = pipeline(STEVENBLACK, Action::Nxdomain);
    for name in ["2no.co.", "WWW.2no.CO.", "a.b.ad-assets.futurecdn.net."] {
        assert!(blocked(&hosts, name), "{name}");
    }
    for name in ["co.", "futurecdn.net.", "example.com."] {
        assert!(!blocked(&hosts, name), "{name}");
    }
    let domains = pipeline(HAGEZI, Action::Nxdomain);
    assert!(blocked(&domains, "telemetry.001-studio.com."));
    assert!(blocked(&domains, "x.0.07c225f3.online."));
    assert!(!blocked(&domains, "001-studio.com."));
}

/// The host's own entries at the head of a hosts file are not blocked: localhost (RFC 6761 §6.3), names of one
/// label, addresses as names (`0.0.0.0 0.0.0.0`), and lines of other addresses.
#[test]
fn the_entries_of_the_host_are_not_blocked() {
    let hosts = pipeline(STEVENBLACK, Action::Nxdomain);
    for name in [
        "localhost.",
        "localhost.localdomain.",
        "local.",
        "printer.local.",
        "broadcasthost.",
        "ip6-allnodes.",
        "0.0.0.0.",
        "x.0.0.0.0.",
    ] {
        assert!(!blocked(&hosts, name), "{name}");
    }
    let other = pipeline("192.168.1.1 router.example\n", Action::Nxdomain);
    assert!(!blocked(&other, "router.example."));
}

#[test]
fn each_action_has_its_reply() {
    for (action, qtype, rcode, data) in [
        (Action::Nxdomain, RecordType::A, Rcode::NXDOMAIN, vec![]),
        (Action::Nodata, RecordType::A, Rcode::NOERROR, vec![]),
        (Action::Refused, RecordType::A, Rcode::REFUSED, vec![]),
        (
            Action::Null,
            RecordType::A,
            Rcode::NOERROR,
            vec![RData::A(Ipv4Addr::UNSPECIFIED)],
        ),
        (
            Action::Null,
            RecordType::AAAA,
            Rcode::NOERROR,
            vec![RData::Aaaa(Ipv6Addr::UNSPECIFIED)],
        ),
        (Action::Null, RecordType::MX, Rcode::NOERROR, vec![]),
    ] {
        let reply =
            ask(&pipeline(HAGEZI, action), "Ad.001zb.com.", qtype, Class::IN).expect("a reply");
        assert_eq!(reply.rcode(), rcode, "{action:?}");
        assert!(!reply.header.flags.contains(Flags::AA), "{action:?}");
        let answer: Vec<_> = reply.answer.iter().map(|r| r.data().into_owned()).collect();
        assert_eq!(answer, data, "{action:?}");
        for record in &reply.answer {
            assert_eq!(record.name.to_string(), "Ad.001zb.com.");
            assert_eq!(record.ttl, Ttl::from_wire(60));
        }
        let options = reply.edns.expect("our OPT record").options;
        assert!(
            matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::BLOCKED),
            "{options:?}"
        );
    }
}

#[test]
fn other_classes_go_on() {
    let hosts = pipeline(STEVENBLACK, Action::Nxdomain);
    assert!(ask(&hosts, "2no.co.", RecordType::A, Class::CH).is_none());
}

#[test]
fn fields_that_are_not_names_are_errors() {
    let text = format!("ads.example\n0.0.0.0 {}.example", "a".repeat(64));
    let mut lists = Lists::new();
    let Err(ListError::Line(error)) = lists.read(List::Block, Origin::Local, &text) else {
        unreachable!("a label of 64 bytes")
    };
    assert_eq!(error.line, 2);
    assert!(matches!(error.kind, LineErrorKind::Name(..)), "{error}");
    assert_eq!(lists.names(List::Block), 0);
}

/// Names are host names: letters, digits, `-` and `_` between dots, not all digits, without escapes, not the root.
#[test]
fn names_are_host_names() {
    for field in [
        "<html>",
        "||ads.example^",
        "https://ads.example/path",
        "ads.example:443",
        "ads..example",
        r"ads\.example",
        "*.*.ads.example",
        "ads.*.example",
        "1.2.3",
        "100%",
        "*.",
        ".",
        "@",
    ] {
        let mut lists = Lists::new();
        let result = lists.read(List::Block, Origin::Local, field);
        assert!(
            matches!(&result, Err(ListError::Line(e)) if e.line == 1
                && matches!(&e.kind, LineErrorKind::Name(f, _) if f == field)),
            "{field}: {result:?}"
        );
    }
    let mut lists = Lists::new();
    let read = lists
        .read(
            List::Block,
            Origin::Local,
            "_dmarc.ads-1.example.\n*.ADS.example\n123.example\nzip\n0.0.0.0 0.0.0.0\n",
        )
        .expect("host names");
    assert_eq!(read.names, 4);
}

/// A byte order mark at the head of a text is no part of its first line.
#[test]
fn a_byte_order_mark_is_left_out() {
    for text in [STEVENBLACK, HAGEZI] {
        let names = lists(&format!("\u{feff}{text}")).names(List::Block);
        assert_eq!(names, lists(text).names(List::Block));
    }
    let pipeline = pipeline("\u{feff}ads.example", Action::Nxdomain);
    assert!(blocked(&pipeline, "ads.example."));
}

/// `*.name` in the lists made for Blocky blocks the name and its subdomains, as its documentation says.
#[test]
fn wildcards_block_the_name_and_its_subdomains() {
    let pipeline = pipeline(WILDCARD, Action::Nxdomain);
    for name in ["adform.net.", "a1.adform.net.", "telemetry.001-studio.com."] {
        assert!(blocked(&pipeline, name), "{name}");
    }
    assert!(!blocked(&pipeline, "001-studio.com."));
}

/// An allowed name lets itself and its subdomains through, whichever parent the blocklist lists.
#[test]
fn allowed_names_are_not_blocked() {
    let mut lists = lists(WILDCARD);
    lists
        .read(List::Allow, Origin::Local, REFERRAL)
        .expect("the allowlist reads");
    let pipeline = with_lists(lists, Action::Nxdomain);
    for name in [
        "a1.adform.net.",
        "x.track.adform.net.",
        "analytics.adjust.com.",
        "go.admost.com.",
    ] {
        assert!(!blocked(&pipeline, name), "{name}");
    }
    for name in ["adform.net.", "b.adform.net.", "admost.com."] {
        assert!(blocked(&pipeline, name), "{name}");
    }
}

/// Names listed twice, in any case or as `*.name`, are counted once.
#[test]
fn duplicates_are_counted_once() {
    let mut lists = lists(STEVENBLACK);
    let again = lists
        .read(List::Block, Origin::Local, STEVENBLACK)
        .expect("the list reads");
    assert_eq!((again.names, again.skipped), (0, 0));
    assert!(again.duplicates > 0);
    let mut lists = Lists::new();
    let read = lists
        .read(
            List::Block,
            Origin::Local,
            "ad-assets.futurecdn.net\nb.ad-assets.futurecdn.net\n*.B.ad-assets.futurecdn.net",
        )
        .expect("the names read");
    assert_eq!((read.names, read.duplicates), (2, 1));
    assert_eq!(lists.names(List::Block), 2);
    assert!(blocked(
        &with_lists(lists, Action::Nxdomain),
        "a.b.ad-assets.futurecdn.net."
    ));
}

/// A downloaded list skips the lines that are not names, and is refused when most are, as is an error page.
#[test]
fn downloaded_lists_skip_lines_that_are_not_names() {
    let mut lists = Lists::new();
    let bad = format!("{HAGEZI}{}.example\n", "a".repeat(64));
    let read = lists
        .read(List::Block, Origin::Downloaded, &bad)
        .expect("most lines read");
    assert_eq!(read.skipped, 1);
    assert!(read.names > 0);
    let names = lists.names(List::Block);
    // The body of a missing file on raw.githubusercontent.com.
    for (text, lines, read) in [("404: Not Found", 1, 0), ("", 0, 0)] {
        assert_eq!(
            lists.read(List::Block, Origin::Downloaded, text),
            Err(ListError::NotAList { lines, read }),
            "{text}"
        );
    }
    assert_eq!(lists.names(List::Block), names);
    assert_eq!(
        lists
            .read(List::Block, Origin::Downloaded, STEVENBLACK)
            .map(|read| read.skipped),
        Ok(0)
    );
    assert_eq!(
        lists.read(List::Allow, Origin::Downloaded, REFERRAL),
        Ok(Read {
            names: lists_of(REFERRAL),
            duplicates: 0,
            skipped: 0
        })
    );
}

/// An error page served with status 200, or a list in Adblock syntax, is refused, not read as names.
#[test]
fn error_pages_and_adblock_lists_are_not_lists() {
    let mut lists = Lists::new();
    for (text, lines) in [(NGINX_404, 7), (ADBLOCK, 30)] {
        assert_eq!(
            lists.read(List::Block, Origin::Downloaded, text),
            Err(ListError::NotAList { lines, read: 0 }),
            "{text}"
        );
    }
    assert_eq!(lists.names(List::Block), 0);
}

/// Checking a downloaded text agrees with reading it, duplicates counted as names.
#[test]
fn a_check_reads_as_a_download_does() {
    let bad = format!("{HAGEZI}{}.example\n", "a".repeat(64));
    for text in [HAGEZI, STEVENBLACK, REFERRAL, &bad, NGINX_404, ADBLOCK, ""] {
        let read = Lists::new()
            .read(List::Block, Origin::Downloaded, text)
            .map(|read| (read.names + read.duplicates, read.skipped));
        let checked = Lists::check(text).map(|read| (read.names, read.skipped));
        assert_eq!(checked, read);
    }
}

/// The names of `text`, one a line, comments left out.
fn lists_of(text: &str) -> usize {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count()
}

/// A downloaded list with half its lines read is a list still.
#[test]
fn a_downloaded_list_half_read_is_a_list() {
    let text = format!("one.example\n{}.example\n", "a".repeat(64));
    let read = Lists::new().read(List::Block, Origin::Downloaded, &text);
    assert_eq!(read.map(|read| (read.names, read.skipped)), Ok((1, 1)));
}
