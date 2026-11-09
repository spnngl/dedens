//! The blocklist plugin (D54, D56) on published lists, in `testdata/plugins/`: the heads of `StevenBlack/hosts`
//! (`stevenblack.hosts`), of the Multi LIGHT domains of `hagezi/dns-blocklists` (`hagezi-light.txt`), of its Multi
//! PRO in the wildcard format (`hagezi-pro-wildcard.txt`) and of its referral allowlist
//! (`hagezi-referral-allow.txt`), each with a few lines of further down, and the `/etc/hosts` of Fedora's `setup`
//! package (`fedora.hosts`, `src.fedoraproject.org/rpms/setup`, rawhide). Blocked answers carry the Extended DNS Error
//! Blocked (RFC 8914 §4.16). Texts that are no lists: the head of the Multi LIGHT in Adblock syntax
//! (`hagezi-light.adblock`) and nginx's 404 page, as `dl-cdn.alpinelinux.org` serves it (`nginx-404.html`).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use dedens_plugins::{
    Action, Blocklist, LineErrorKind, List, ListError, Lists, MAX_HOPS, Merged, Names, Origin,
    Read, Tlds,
};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, Flags, Message, Name, Query, Question, Rcode, Record, RecordType, Transport, Ttl,
};
use dedens_server::{Answer, Forward, Pipeline, Plugin, Stage, Step};
use dedens_testkit::{captured, dnssec, message};

const STEVENBLACK: &str = include_str!("../../../testdata/plugins/stevenblack.hosts");
const HAGEZI: &str = include_str!("../../../testdata/plugins/hagezi-light.txt");
const WILDCARD: &str = include_str!("../../../testdata/plugins/hagezi-pro-wildcard.txt");
const REFERRAL: &str = include_str!("../../../testdata/plugins/hagezi-referral-allow.txt");
const ADBLOCK: &str = include_str!("../../../testdata/plugins/hagezi-light.adblock");
const NGINX_404: &str = include_str!("../../../testdata/plugins/nginx-404.html");
const FEDORA: &str = include_str!("../../../testdata/plugins/fedora.hosts");

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
    match pipeline.query(
        &query,
        Transport::Udp,
        Ipv4Addr::LOCALHOST.into(),
        0,
        &mut out,
    ) {
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

/// Names whose first label starts with `localhost`, any case, are the host's own: Fedora's `localhost4.localdomain4`
/// and `localhost6.localdomain6` read as no entry.
#[test]
fn names_starting_with_localhost_are_the_hosts() {
    assert_eq!(lists(FEDORA).names(List::Block), 0);
    assert_eq!(lists("0.0.0.0 LocalHost4.example\n").names(List::Block), 0);
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

/// A name is blocked whatever the class asked, ANY (QCLASS 255) and NONE included (D110): a class other than IN
/// must not walk around the list. Names not listed go on in every class.
#[test]
fn every_class_is_blocked() {
    let hosts = pipeline(STEVENBLACK, Action::Nxdomain);
    for class in [Class::IN, Class::ANY, Class::NONE, Class::CH, Class::HS] {
        let reply = ask(&hosts, "www.2no.co.", RecordType::A, class);
        assert_eq!(reply.map(|r| r.rcode()), Some(Rcode::NXDOMAIN), "{class}");
        assert!(ask(&hosts, "example.com.", RecordType::A, class).is_none());
    }
}

/// `Action::Null` answers with records of class IN: to IN and ANY questions only, no data to another class.
#[test]
fn null_records_answer_in_and_any_only() {
    let hosts = pipeline(HAGEZI, Action::Null);
    for (class, answers) in [
        (Class::IN, 1),
        (Class::ANY, 1),
        (Class::CH, 0),
        (Class::NONE, 0),
    ] {
        let reply = ask(&hosts, "Ad.001zb.com.", RecordType::A, class).expect("a reply");
        assert_eq!(reply.rcode(), Rcode::NOERROR, "{class}");
        assert_eq!(reply.answer.len(), answers, "{class}");
    }
}

/// A name of the 127 labels the longest has (255 bytes on the wire) blocks itself, and a listed parent blocks a
/// name 126 labels deep: the walk by suffixes reaches the first label, and no more (D110).
#[test]
fn the_deepest_names_are_looked_up() {
    let deepest = "a.".repeat(127);
    let parent = "a.".repeat(126);
    let pipeline = pipeline(&format!("{deepest}\nexample.com\n"), Action::Nxdomain);
    assert!(blocked(&pipeline, &deepest));
    assert!(!blocked(&pipeline, &parent));
    let below = format!("{}example.com.", "a.".repeat(121));
    assert!(blocked(&pipeline, &below));
    let other = format!("{}example.org.", "a.".repeat(121));
    assert!(!blocked(&pipeline, &other));
}

/// Suffixes are looked up whole labels at a time: the same bytes split in other labels, or listed with other
/// labels in front, are other names.
#[test]
fn label_boundaries_count() {
    let pipeline = pipeline("a.bc.example\nx.y.z.example.net\n", Action::Nxdomain);
    for name in ["a.bc.example.", "q.a.bc.example.", "A.BC.Example."] {
        assert!(blocked(&pipeline, name), "{name}");
    }
    for name in [
        "ab.c.example.",
        "abc.example.",
        "bc.example.",
        "a.b.c.example.",
        "y.z.example.net.",
        "z.example.net.",
        "x.y.z.example.org.",
        "w.y.z.example.net.",
    ] {
        assert!(!blocked(&pipeline, name), "{name}");
    }
    for name in ["x.y.z.example.net.", "w.x.y.z.example.net."] {
        assert!(blocked(&pipeline, name), "{name}");
    }
}

/// An allowed name deeper than any blocked one still lets its subdomains through, and one shallower than the
/// blocked ones does not matter to names outside it: the walk goes on as far as the allowlist needs (D110).
#[test]
fn an_allowed_name_deeper_than_the_blocked_ones_wins() {
    let mut lists = lists("example.com\n");
    lists
        .read(List::Allow, Origin::Local, "a.b.c.d.example.com\n")
        .expect("the allowlist reads");
    let pipeline = with_lists(lists, Action::Nxdomain);
    assert!(!blocked(&pipeline, "a.b.c.d.example.com."));
    assert!(!blocked(&pipeline, "x.a.b.c.d.example.com."));
    assert!(blocked(&pipeline, "b.c.d.example.com."));
    assert!(blocked(&pipeline, "z.a.b.c.d.other.example.com."));
}

/// An allowed name of a few labels lets a name 119 labels under it through.
#[test]
fn a_deep_name_under_an_allowed_parent_is_not_blocked() {
    let mut lists = lists("example.com\n");
    lists
        .read(List::Allow, Origin::Local, "ok.example.com\n")
        .expect("the allowlist reads");
    let pipeline = with_lists(lists, Action::Nxdomain);
    assert!(!blocked(
        &pipeline,
        &format!("{}ok.example.com.", "a.".repeat(119))
    ));
    assert!(blocked(
        &pipeline,
        &format!("{}no.example.com.", "a.".repeat(119))
    ));
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
            "_dmarc.ads-1.example.\n*.ADS.example\n123.example\nzip.example\n0.0.0.0 0.0.0.0\n",
        )
        .expect("host names");
    assert_eq!(read.names, 4);
}

/// A plain line of one label, `com` or `*.com`, would block or allow a whole top-level domain: a local text is
/// refused with its line, in either list, and a downloaded one skips it, counted (D118, S15.b).
#[test]
fn a_top_level_domain_is_no_plain_entry() {
    for (list, field) in [
        (List::Block, "com"),
        (List::Block, "*.com"),
        (List::Block, "COM."),
        (List::Allow, "com"),
    ] {
        let mut lists = Lists::new();
        let result = lists.read(list, Origin::Local, &format!("ads.example\n# c\n{field}\n"));
        assert!(
            matches!(&result, Err(ListError::Line(e)) if e.line == 3
                && matches!(&e.kind, LineErrorKind::SingleLabel(f) if f == field)),
            "{field}: {result:?}"
        );
        assert_eq!(lists.names(list), 0);
    }
    let text = "one.example\ntwo.example\ncom\n";
    let read = Lists::new().read(List::Block, Origin::Downloaded, text);
    assert_eq!(read.map(|read| (read.names, read.skipped)), Ok((2, 1)));
    // A download is checked for its format; the lists reading the saved copy decide on a name of one label.
    assert_eq!(
        Names::downloaded(text)
            .check(Tlds::Allow)
            .map(|read| (read.names, read.skipped)),
        Ok((3, 0))
    );
    let mut lists = Lists::new();
    lists
        .read(List::Block, Origin::Downloaded, text)
        .expect("most lines read");
    let pipeline = with_lists(lists, Action::Nxdomain);
    assert!(!blocked(&pipeline, "com."));
    assert!(!blocked(&pipeline, "example.com."));
}

/// A list of top-level domains is read by lists made for it (`tlds`): `zip` is a name then, in a plain list only
/// (D118).
#[test]
fn a_top_level_domain_is_an_entry_when_the_lists_take_them() {
    let mut lists = Lists::with_tlds(Tlds::Allow);
    let read = lists
        .read(List::Block, Origin::Local, "zip\n*.mov\nads.example\n")
        .expect("top-level domains read");
    assert_eq!((read.names, read.skipped), (3, 0));
    let pipeline = with_lists(lists, Action::Nxdomain);
    assert!(blocked(&pipeline, "zip."));
    assert!(blocked(&pipeline, "www.example.zip."));
    assert!(blocked(&pipeline, "mov."));
    assert!(!blocked(&pipeline, "example.com."));
}

/// The exception: a hosts line leaves a name of one label out, as before. Hosts files list the host's own
/// entries (`127.0.0.1 localhost`, `255.255.255.255 broadcasthost`), which no list of someone else's should fail
/// on; the name is not blocked, so no top-level domain is (D54, D118).
#[test]
fn a_hosts_line_leaves_a_top_level_domain_out() {
    let mut lists = Lists::new();
    let read = lists
        .read(
            List::Block,
            Origin::Local,
            "0.0.0.0 com\n127.0.0.1 localhost broadcasthost\n0.0.0.0 ads.example\n",
        )
        .expect("hosts lines read");
    assert_eq!((read.names, read.skipped), (1, 0));
    let pipeline = with_lists(lists, Action::Nxdomain);
    assert!(!blocked(&pipeline, "example.com."));
    assert!(blocked(&pipeline, "ads.example."));
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

/// Texts read into one list add up, names of the same number of labels in both included: each is
/// blocked, and the allowlist of each text lets its own names through.
#[test]
fn texts_add_up() {
    let mut lists = lists("a.example\n");
    lists
        .read(List::Block, Origin::Local, "b.example\nc.d.example\n")
        .expect("the second text reads");
    lists
        .read(List::Allow, Origin::Local, "x.b.example\n")
        .expect("the allowlist reads");
    lists
        .read(List::Allow, Origin::Local, "y.c.d.example\n")
        .expect("the second allowlist reads");
    let pipeline = with_lists(lists, Action::Nxdomain);
    for name in ["a.example.", "b.example.", "z.c.d.example.", "c.d.example."] {
        assert!(blocked(&pipeline, name), "{name}");
    }
    for name in ["x.b.example.", "w.x.b.example.", "y.c.d.example."] {
        assert!(!blocked(&pipeline, name), "{name}");
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
    // A name listed twice stays listed.
    let mut twice = Lists::new();
    twice
        .read(List::Block, Origin::Local, "x.example\nX.EXAMPLE.\n")
        .expect("the names read");
    assert!(blocked(&with_lists(twice, Action::Nxdomain), "x.example."));
    assert!(blocked(
        &with_lists(lists, Action::Nxdomain),
        "a.b.ad-assets.futurecdn.net."
    ));
}

/// The lists count the names listed more than once, twice in a text or held from an earlier text, per list.
#[test]
fn the_lists_count_their_duplicates() {
    let mut lists = Lists::new();
    lists
        .read(
            List::Block,
            Origin::Local,
            "a.example\nA.example.\nb.example\n",
        )
        .expect("the names read");
    assert_eq!(lists.duplicates(List::Block), 1);
    lists
        .read(List::Block, Origin::Local, "b.example\nc.example\n")
        .expect("the names read");
    assert_eq!(lists.duplicates(List::Block), 2);
    assert_eq!(lists.duplicates(List::Allow), 0);
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

/// Checking a downloaded text agrees with reading it, duplicates counted as names, for lists taking top-level
/// domains or not.
#[test]
fn a_check_reads_as_a_download_does() {
    let bad = format!("{HAGEZI}{}.example\n", "a".repeat(64));
    for text in [HAGEZI, STEVENBLACK, REFERRAL, &bad, NGINX_404, ADBLOCK, ""] {
        let read = Lists::new()
            .read(List::Block, Origin::Downloaded, text)
            .map(|read| (read.names + read.duplicates, read.skipped));
        let checked = Names::downloaded(text)
            .check(Tlds::Refuse)
            .map(|read| (read.names + read.duplicates, read.skipped));
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

/// D120: a text read once is added to the lists of any stages, each reading its plain lines of one label as it
/// says, and reads as `Lists::read` reads it; a text added twice counts its names once.
#[test]
fn a_text_read_once_is_added_to_any_lists() {
    let text = "one.example\ntwo.example\nzip\none.example\n";
    let names = Names::downloaded(text);
    let mut refusing = Lists::new();
    let mut taking = Lists::with_tlds(Tlds::Allow);
    for (lists, expected) in [
        (
            &mut refusing,
            Lists::new().read(List::Block, Origin::Downloaded, text),
        ),
        (
            &mut taking,
            Lists::with_tlds(Tlds::Allow).read(List::Block, Origin::Downloaded, text),
        ),
    ] {
        assert_eq!(lists.add(List::Block, &names), expected);
    }
    assert_eq!(
        (refusing.names(List::Block), taking.names(List::Block)),
        (2, 3)
    );
    assert!(!blocked(&with_lists(refusing, Action::Nxdomain), "zip."));
    assert!(blocked(&with_lists(taking, Action::Nxdomain), "www.zip."));
    let mut twice = Lists::new();
    twice.add(List::Block, &names).expect("a list");
    let again = twice.add(List::Block, &names).expect("a list");
    assert_eq!((again.names, again.duplicates), (0, 3));
    assert_eq!(twice.names(List::Block), 2);
    // Not a list for lists refusing its one-label lines, a list for those taking them.
    let tlds = Names::downloaded("zip\nmov\nads.example\n");
    assert_eq!(
        Lists::new().add(List::Block, &tlds),
        Err(ListError::NotAList { lines: 3, read: 1 })
    );
    assert!(
        Lists::with_tlds(Tlds::Allow)
            .add(List::Block, &tlds)
            .is_ok()
    );
}

/// D120: names kept in several texts block and allow as they do read into one: a name listed in one text, allowed by
/// another, whatever the number of labels of each.
#[test]
fn texts_kept_apart_answer_as_one() {
    let mut lists = Lists::new();
    for text in ["a.example\n", "b.example\nc.d.example\n", "e.f.g.example\n"] {
        lists
            .add(
                List::Block,
                &Names::local(Tlds::Refuse, text).expect("a list"),
            )
            .expect("added");
    }
    for text in ["x.b.example\n", "y.c.d.example\n"] {
        lists
            .add(
                List::Allow,
                &Names::local(Tlds::Refuse, text).expect("a list"),
            )
            .expect("added");
    }
    assert_eq!(lists.names(List::Block), 4);
    let pipeline = with_lists(lists, Action::Nxdomain);
    for name in [
        "a.example.",
        "z.a.example.",
        "b.example.",
        "c.d.example.",
        "h.e.f.g.example.",
    ] {
        assert!(blocked(&pipeline, name), "{name}");
    }
    for name in [
        "x.b.example.",
        "w.x.b.example.",
        "y.c.d.example.",
        "f.g.example.",
    ] {
        assert!(!blocked(&pipeline, name), "{name}");
    }
}

/// D120: the texts of the published lists read apart, in chunks of lines, merged into one set per side answer as the
/// same texts read into one `Lists`, for lists taking top-level domains or not: the same counts, and the same
/// answer for each name they hold, its parent and a child of it.
#[test]
fn published_lists_read_apart_and_merged_answer_as_read_together() {
    let blocks = [STEVENBLACK, HAGEZI, WILDCARD];
    for tlds in [Tlds::Refuse, Tlds::Allow] {
        let mut together = Lists::with_tlds(tlds);
        let mut apart = [Vec::new(), Vec::new()];
        for (list, texts) in [(List::Block, &blocks[..]), (List::Allow, &[REFERRAL][..])] {
            for text in texts {
                together
                    .read(list, Origin::Local, text)
                    .expect("the list reads");
                let lines: Vec<&str> = text.lines().collect();
                for chunk in lines.chunks(37) {
                    let chunk = format!("{}\n", chunk.join("\n"));
                    let side = &mut apart[usize::from(list == List::Allow)];
                    side.push(Names::local(tlds, &chunk).expect("a chunk reads"));
                }
            }
        }
        // A text listed again in whole: every name of it a duplicate.
        apart[0].push(Names::local(tlds, STEVENBLACK).expect("the list reads"));
        together
            .read(List::Block, Origin::Local, STEVENBLACK)
            .expect("the list reads");
        let [block, allow] = apart.map(|sources| Merged::new(tlds, &sources).expect("merged"));
        let merged = Lists::from_merged(tlds, block, allow);
        for list in [List::Block, List::Allow] {
            assert_eq!(merged.names(list), together.names(list));
            assert_eq!(merged.duplicates(list), together.duplicates(list));
        }
        let together = with_lists(together, Action::Nxdomain);
        let merged = with_lists(merged, Action::Nxdomain);
        let mut asked = 0;
        for token in blocks
            .iter()
            .chain(&[REFERRAL])
            .flat_map(|text| text.split_whitespace())
        {
            let token = token.strip_prefix("*.").unwrap_or(token);
            let Some((_, parent)) = token.split_once('.') else {
                continue;
            };
            for name in [token.to_owned(), format!("www.{token}"), parent.to_owned()] {
                let name = format!("{}.", name.trim_end_matches('.'));
                if name.parse::<Name<'_>>().is_err() {
                    continue;
                }
                assert_eq!(blocked(&merged, &name), blocked(&together, &name), "{name}");
                asked += 1;
            }
        }
        assert!(asked > 300, "{asked}");
    }
}

/// D120: a local text read as taking top-level domains, added to lists that refuse them, leaves them out.
#[test]
fn a_local_text_taking_top_level_domains_adds_none_to_lists_refusing_them() {
    let names = Names::local(Tlds::Allow, "zip\nads.example\n").expect("a list");
    let mut refusing = Lists::new();
    assert_eq!(
        refusing.add(List::Block, &names).map(|read| read.names),
        Ok(1)
    );
    assert!(!blocked(&with_lists(refusing, Action::Nxdomain), "zip."));
    let merged = Merged::new(Tlds::Refuse, &[names]).expect("merged");
    assert_eq!(merged.len(), 1);
}

/// D120: a merged set holds each name once and counts the others, in a text or across texts; its clones share it,
/// a set merged again from the same texts does not.
#[test]
fn a_merged_set_counts_its_duplicates_and_is_shared_by_its_clones() {
    let first = Names::local(Tlds::Refuse, "a.example\nA.example.\nb.example\n").expect("a list");
    let second = Names::local(Tlds::Refuse, "b.example\nc.example\n").expect("a list");
    let sources = [first, second];
    let merged = Merged::new(Tlds::Refuse, &sources).expect("merged");
    assert_eq!((merged.len(), merged.duplicates()), (3, 2));
    assert!(!merged.is_empty());
    assert!(merged.shares(&merged.clone()));
    assert!(!merged.shares(&Merged::new(Tlds::Refuse, &sources).expect("merged")));
    assert!(Merged::new(Tlds::Refuse, &[]).expect("merged").is_empty());
}

/// D120: a text's names, top-level domains included, each once; its clones are the same reading, the text read again
/// another.
#[test]
fn names_are_counted_once_and_shared_by_their_clones() {
    let text = "zip\nads.example\nzip\n";
    let names = Names::local(Tlds::Allow, text).expect("a list");
    assert_eq!(names.len(), 2);
    assert!(!names.is_empty());
    assert_eq!(
        names
            .check(Tlds::Allow)
            .map(|read| (read.names, read.duplicates)),
        Ok((2, 1))
    );
    assert!(names.same(&names.clone()));
    assert!(!names.same(&Names::local(Tlds::Allow, text).expect("a list")));
    assert!(Names::downloaded("").is_empty());
}

/// D120: a downloaded text of which a line fails after a name was read leaves that name out, whole line.
#[test]
fn a_line_that_fails_leaves_none_of_its_names() {
    let text = "0.0.0.0 one.example two.example !bad\nthree.example\n";
    let names = Names::downloaded(text);
    assert_eq!(names.len(), 1);
    assert_eq!(names.check(Tlds::Allow).map(|read| read.skipped), Ok(1));
}

/// The captures whose answers hold a CNAME or a DNAME, with the question each answers (D118).
fn chains() -> Vec<Message<'static>> {
    vec![
        // `www.ripe.net.` CNAME `www.ripe.net.edgekey.net.` CNAME `e337066.dscb.akamaiedge.net.`
        dnssec::response("cname_to_insecure"),
        // `www.icann.org.` CNAME `www.icann.org.cdn.cloudflare.net.`
        dnssec::response("cname_cross_zone"),
        // `www.github.com.` CNAME `github.com.`, and its address.
        message(&captured("cname_chain")),
        // `dname.sidnlabs.nl.` DNAME `example.nl.`, and the CNAME made from it.
        dnssec::response("dname_answer"),
    ]
}

/// The targets of the CNAME records of `response`, as text.
fn targets(response: &Message<'_>) -> Vec<String> {
    response
        .answer
        .iter()
        .filter_map(|r| match r.data() {
            RData::Cname(target) => Some(target.to_string()),
            _ => None,
        })
        .collect()
}

fn blocklist(block: &str, allow: &str, action: Action) -> Blocklist {
    let mut lists = lists(block);
    lists
        .read(List::Allow, Origin::Local, allow)
        .expect("the allowlist reads");
    Blocklist::new(lists, action, Ttl::from_wire(60))
}

/// The answer `blocklist` gives instead of `response`, to a query for the question of `response` (as the one
/// asked), if any.
fn review<'b>(blocklist: &'b Blocklist, response: &Message<'_>) -> Option<Answer<'b>> {
    let question = response.questions.first().expect("a question").clone();
    let query = Message::query(7, question).to_vec().expect("a query fits");
    let query = Query::read(&query).expect("a query reads");
    blocklist.reviewer()?.review(&query, response)
}

/// S13: a target of a chain listed, as `t.site. CNAME ads.example.` with `ads.example` blocked, blocks the
/// response, as a query for the target does, whichever of the captured chains and whichever of its hops (D118).
#[test]
fn a_listed_cname_target_blocks_the_response() {
    for response in chains() {
        let targets = targets(&response);
        assert!(!targets.is_empty(), "{:?}", response.questions);
        for target in &targets {
            let blocklist = blocklist(&format!("{target}\n"), "", Action::Nxdomain);
            let answer = review(&blocklist, &response).expect(target);
            assert_eq!(answer.rcode, Rcode::NXDOMAIN, "{target}");
            assert_eq!(answer.error, Some(InfoCode::BLOCKED));
            assert!(!answer.authoritative);
            // A parent of the target blocks it as well.
            let (_, parent) = target
                .split_once('.')
                .expect("a target of two labels at least");
            if parent.trim_end_matches('.').contains('.') {
                let blocklist = blocklist_of(parent);
                assert!(review(&blocklist, &response).is_some(), "{parent}");
            }
        }
        let other = blocklist("ads.example\n", "", Action::Nxdomain);
        assert!(review(&other, &response).is_none(), "{targets:?}");
    }
}

fn blocklist_of(block: &str) -> Blocklist {
    blocklist(&format!("{block}\n"), "", Action::Nxdomain)
}

/// A DNAME blocks as a CNAME does: the response of `dname_answer` with its synthesized CNAME left out holds
/// `example.nl.` as the DNAME's target only (RFC 6672 §2.1).
#[test]
fn a_listed_dname_target_blocks_the_response() {
    let mut response = dnssec::response("dname_answer");
    assert_eq!(
        targets(&response),
        ["wWw.example.nl."],
        "as the server wrote it, 0x20 included"
    );
    response.answer.retain(|r| r.rtype() != RecordType::CNAME);
    assert!(
        response
            .answer
            .iter()
            .any(|r| r.rtype() == RecordType::DNAME)
    );
    assert!(review(&blocklist_of("example.nl"), &response).is_some());
    assert!(review(&blocklist_of("www.example.nl"), &response).is_none());
    assert!(review(&blocklist_of("ads.example"), &response).is_none());
}

/// A DNAME rewrites the names below its owner, not the owner itself (RFC 6672 §2.1): the DNAME of `dname_answer`
/// answering a query for its owner leads nowhere, whatever its target.
#[test]
fn a_dname_does_not_redirect_its_owner() {
    let mut response = dnssec::response("dname_answer");
    let owner = response
        .answer
        .iter()
        .find(|r| r.rtype() == RecordType::DNAME)
        .expect("a DNAME")
        .name
        .clone();
    response.questions = vec![Question::new(owner, RecordType::DNAME)];
    assert!(review(&blocklist_of("example.nl"), &response).is_none());
}

/// The order of the records in the section does not change what a response leads to: with the CNAME written before
/// the DNAME it was made from, the DNAME's target is still checked, though the CNAME's target is allowed.
#[test]
fn a_dname_after_its_cname_is_checked() {
    let mut response = dnssec::response("dname_answer");
    let blocklist = blocklist("example.nl\n", "www.example.nl\n", Action::Nxdomain);
    assert!(review(&blocklist, &response).is_some(), "as captured");
    response
        .answer
        .sort_by_key(|r| r.rtype() != RecordType::CNAME);
    assert_eq!(response.answer[0].rtype(), RecordType::CNAME);
    assert!(review(&blocklist, &response).is_some(), "the CNAME first");
}

/// The allowlist lets a target through as it lets a query name: itself and its subdomains. A query name the
/// allowlist lets through is not reviewed at all, so that it can be unblocked without allowing what it points to
/// (D118).
#[test]
fn the_allowlist_decides_for_targets_as_for_names() {
    let response = dnssec::response("cname_to_insecure");
    let listed = "akamaiedge.net\n";
    for (allow, passes) in [
        ("e337066.dscb.akamaiedge.net\n", true),
        ("dscb.akamaiedge.net\n", true),
        ("akamaiedge.net\n", true),
        ("other.akamaiedge.net\n", false),
        ("www.ripe.net\n", true),
        ("ripe.net\n", true),
    ] {
        let blocklist = blocklist(listed, allow, Action::Nxdomain);
        assert_eq!(review(&blocklist, &response).is_none(), passes, "{allow}");
    }
}

/// The reply is the one of the action, as for a blocked query name: each action, and the null addresses for the
/// question's type, whatever the chain.
#[test]
fn a_blocked_response_is_answered_as_the_action_says() {
    let response = dnssec::response("cname_to_insecure");
    for (action, rcode, records) in [
        (Action::Nxdomain, Rcode::NXDOMAIN, false),
        (Action::Nodata, Rcode::NOERROR, false),
        (Action::Refused, Rcode::REFUSED, false),
        (Action::Null, Rcode::NOERROR, true),
    ] {
        let blocklist = blocklist("akamaiedge.net\n", "", action);
        let answer = review(&blocklist, &response).expect("blocked");
        assert_eq!((answer.rcode, answer.records.is_some()), (rcode, records));
        assert_eq!(answer.error, Some(InfoCode::BLOCKED));
    }
}

/// No name listed, nothing to review: the plugin leaves responses to go undecoded.
#[test]
fn a_blocklist_of_allowed_names_only_reviews_nothing() {
    let none = Blocklist::new(Lists::new(), Action::Nxdomain, Ttl::from_wire(60));
    assert!(none.reviewer().is_none());
    let allow_only = blocklist("", "ads.example\n", Action::Nxdomain);
    assert!(allow_only.reviewer().is_none());
    assert!(blocklist_of("ads.example").reviewer().is_some());
}

/// Hops are counted along the chain from the query name: up to [`MAX_HOPS`] are followed, more is SERVFAIL, not
/// Blocked, whatever the chain points to; records on no chain are not hops (D118). No capture has so long a chain:
/// these are made of records of the shape of `cname_to_insecure`'s.
#[test]
fn a_chain_over_the_bound_is_servfail() {
    let blocklist = blocklist_of("ads.example");
    let cname = |from: &str, to: &str| {
        let owner: Name<'static> = from.parse().expect("a name");
        let target: Name<'static> = to.parse().expect("a name");
        Record::new(owner, Class::IN, Ttl::from_wire(60), &RData::Cname(target))
    };
    let chain = |hops: usize| {
        let answer = (0..hops)
            .map(|i| {
                cname(
                    &format!("n{i}.chain.test."),
                    &format!("n{}.chain.test.", i + 1),
                )
            })
            .collect();
        Message {
            questions: vec![Question::new(
                "n0.chain.test.".parse().expect("a name"),
                RecordType::A,
            )],
            answer,
            ..Message::default()
        }
    };
    assert!(review(&blocklist, &chain(MAX_HOPS)).is_none());
    let long = review(&blocklist, &chain(MAX_HOPS + 1)).expect("too long");
    assert_eq!(long.rcode, Rcode::SERVFAIL);
    assert_ne!(long.error, Some(InfoCode::BLOCKED));
    // Unrelated records are not hops.
    let mut response = chain(MAX_HOPS);
    response
        .answer
        .extend((0..40).map(|i| cname(&format!("x{i}.other.test."), "y.other.test.")));
    assert!(review(&blocklist, &response).is_none());
    // The target of the hop past the limit is looked at, and the chain is not followed further.
    response
        .answer
        .push(cname("n16.chain.test.", "ads.example."));
    assert!(review(&blocklist, &response).is_some_and(|a| a.rcode == Rcode::NXDOMAIN));
    // A loop is a chain that never ends.
    let looped = Message {
        answer: vec![
            cname("n0.chain.test.", "n1.chain.test."),
            cname("n1.chain.test.", "n0.chain.test."),
        ],
        ..chain(0)
    };
    assert!(review(&blocklist, &looped).is_some_and(|a| a.rcode == Rcode::SERVFAIL));
}

/// A DNAME and the CNAME made from it are one hop (RFC 6672 §2.2), and the chain goes on from the target of the CNAME:
/// the capture holds a DNAME and the CNAME made from it, and the listed name is found through either.
#[test]
fn a_dname_and_its_cname_are_one_hop() {
    let response = dnssec::response("dname_answer");
    let types = response
        .answer
        .iter()
        .map(Record::rtype)
        .collect::<Vec<_>>();
    assert!(types.contains(&RecordType::DNAME) && types.contains(&RecordType::CNAME));
    assert!(review(&blocklist_of("example.nl"), &response).is_some());
    assert!(review(&blocklist_of("ads.example"), &response).is_none());
}

/// The answer of a pipeline whose upstream gives `response` to a query for the question of `response`.
fn resolve(pipeline: &Pipeline, response: &Message<'_>) -> Message<'static> {
    let wire = response.to_vec().expect("a response fits");
    let question = response.questions.first().expect("a question").clone();
    let query = Message::query(7, question).to_vec().expect("a query fits");
    let mut out = vec![0; 65535];
    let Step::Upstream(upstream) = pipeline.query(
        &query,
        Transport::Udp,
        Ipv4Addr::LOCALHOST.into(),
        0,
        &mut out,
    ) else {
        unreachable!("the query name is not listed")
    };
    let Step::Reply(len) = pipeline.receive(upstream, Some(&wire), 0, &mut out) else {
        unreachable!("a reply")
    };
    Message::decode(&out[..len])
        .expect("the reply decodes")
        .message
        .into_owned()
}

/// S13 end to end: `www.ripe.net.` is not listed, but its chain ends in a listed name: NXDOMAIN with EDE Blocked
/// instead of the addresses of the tracker; a list that holds none of the chain leaves the response as it is.
#[test]
fn a_chain_to_a_listed_name_is_not_served() {
    let response = dnssec::response("cname_to_insecure");
    let pipeline = pipeline("akamaiedge.net\n", Action::Nxdomain);
    let reply = resolve(&pipeline, &response);
    assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NXDOMAIN, 0));
    let options = reply.edns.expect("our OPT record").options;
    assert!(
        matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::BLOCKED),
        "{options:?}"
    );
    let pipeline = pipeline_of("ads.example\n");
    let reply = resolve(&pipeline, &response);
    assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NOERROR, 5));
}

fn pipeline_of(text: &str) -> Pipeline {
    pipeline(text, Action::Nxdomain)
}
