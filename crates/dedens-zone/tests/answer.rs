//! What a zone answers: RFC 1034 §4.3.2 and the examples of §6.2 (on the root zone of §6.1), RFC 4592 §2.2.1 and §3
//! (wildcards), RFC 6672 §2.2, §3, §6 (DNAME), RFC 2308 §3 (the SOA of a negative answer), RFC 8482 §4.2 (ANY),
//! RFC 4035 §3.1.4.1 (DS at a delegation), RFC 6604 §2.1 (AA and RCODE after a chain), RFC 9471 §3.1 (glue and
//! TC). D206 records each choice.

use std::fmt::Write;

use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Header, MAX_MESSAGE_LEN, Message, Question, Rcode, RecordType};
use dedens_testkit::dns;
use dedens_zone::{Answer, End, Limits, Link, MAX_CHAIN, Zone};

use crate::util::{load_files, zone_file};

/// What a response holds, as lines of zone text with the TAB turned into a space.
struct Reply {
    rcode: Rcode,
    aa: bool,
    answer: Vec<String>,
    authority: Vec<String>,
    additional: Vec<String>,
    required_glue: usize,
}

fn text(section: &[dedens_proto::Record<'_>]) -> Vec<String> {
    section
        .iter()
        .map(|record| record.to_string().replace('\t', " "))
        .collect()
}

/// The zone `origin` of `text`.
fn zone(origin: &str, text: &str) -> Zone {
    load_files(origin, text, None, &[], &Limits::default())
        .expect("a valid zone")
        .zone
}

/// A zone `example.` with `extra` after its apex: the SOA (TTL 2 h, MINIMUM 10 min) and an NS.
fn example(extra: &str) -> Zone {
    zone(
        "example.",
        &format!(
            "$ORIGIN example.\n$TTL 1h\n@ 2h SOA ns hostmaster 1 1d 2h 4w 10m\n@ NS ns\nns A 192.0.2.1\n{extra}"
        ),
    )
}

fn ask_class(zone: &Zone, name: &str, rtype: RecordType, class: Class) -> Reply {
    let mut question = Question::new(dns(name), rtype);
    question.qclass = class;
    let answer = zone.answer(&question);
    reply(zone, &answer, &question)
}

fn reply(zone: &Zone, answer: &Answer<'_>, question: &Question<'_>) -> Reply {
    let mut message = Message {
        header: Header {
            flags: Flags::QR,
            ..Header::default()
        },
        questions: vec![question.clone()],
        ..Message::default()
    };
    let glue = answer.fill(zone, &mut message, MAX_MESSAGE_LEN);
    Reply {
        rcode: message.rcode(),
        aa: message.header.flags.contains(Flags::AA),
        answer: text(&message.answer),
        authority: text(&message.authority),
        additional: text(&message.additional),
        required_glue: glue.required(),
    }
}

fn ask(zone: &Zone, name: &str, rtype: RecordType) -> Reply {
    ask_class(zone, name, rtype, Class::IN)
}

/// The bytes as lowercase hexadecimal.
fn hex(wire: &[u8]) -> String {
    wire.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// `d DNAME target` as zone text, in the generic form (RFC 3597 §5) the zone loader reads DNAME in.
fn dname(owner: &str, target: &str) -> String {
    let wire = dns(target).to_wire(&mut [0; 255]).to_vec();
    let hex = hex(&wire);
    format!("{owner} DNAME \\# {} {hex}\n", wire.len())
}

/// The DNAME record as the reply prints it: a type with no typed RDATA is shown in the generic form.
fn dname_text(owner: &str, target: &str) -> String {
    let wire = dns(target).to_wire(&mut [0; 255]).to_vec();
    let hex = hex(&wire);
    format!("{owner} 3600 IN DNAME \\# {} {hex}", wire.len())
}

// --- RFC 1034 §6.2, on the root zone of §6.1 ---

const ROOT: &str = "$ORIGIN .
$TTL 86400
. IN SOA SRI-NIC.ARPA. HOSTMASTER.SRI-NIC.ARPA. 870611 1800 300 604800 86400
  NS A.ISI.EDU.
  NS C.ISI.EDU.
  NS SRI-NIC.ARPA.
MIL. 86400 NS SRI-NIC.ARPA.
     86400 NS A.ISI.EDU.
EDU. 86400 NS SRI-NIC.ARPA.
     86400 NS C.ISI.EDU.
SRI-NIC.ARPA. A 26.0.0.73
  A 10.0.0.51
  MX 0 SRI-NIC.ARPA.
  HINFO DEC-2060 TOPS20
ACC.ARPA. A 26.6.0.65
  HINFO PDP-11/70 UNIX
  MX 10 ACC.ARPA.
USC-ISIC.ARPA. CNAME C.ISI.EDU.
73.0.0.26.IN-ADDR.ARPA. PTR SRI-NIC.ARPA.
A.ISI.EDU. 86400 A 26.3.0.103
C.ISI.EDU. 86400 A 10.0.0.52
";

fn root() -> Zone {
    zone(".", ROOT)
}

const SOA_ROOT: &str =
    ". 86400 IN SOA SRI-NIC.ARPA. HOSTMASTER.SRI-NIC.ARPA. 870611 1800 300 604800 86400";

#[test]
fn s6_2_1_an_address_is_answered_with_aa_and_nothing_else() {
    let r = ask(&root(), "SRI-NIC.ARPA.", RecordType::A);
    assert!(r.aa);
    assert_eq!(r.rcode, Rcode::NOERROR);
    assert_eq!(
        r.answer,
        [
            "SRI-NIC.ARPA. 86400 IN A 26.0.0.73",
            "SRI-NIC.ARPA. 86400 IN A 10.0.0.51"
        ]
    );
    assert_eq!((r.authority, r.additional), (vec![], vec![]));
}

#[test]
fn s6_2_2_any_is_one_rrset_the_lowest_type_not_all_of_them() {
    // RFC 1034 answers with every RRset; RFC 8482 §4.2 allows one, D206 chooses the lowest type, as Knot does.
    let r = ask(&root(), "SRI-NIC.ARPA.", RecordType::ANY);
    assert_eq!(
        r.answer,
        [
            "SRI-NIC.ARPA. 86400 IN A 26.0.0.73",
            "SRI-NIC.ARPA. 86400 IN A 10.0.0.51"
        ]
    );
}

#[test]
fn s6_2_3_an_mx_answer_has_the_addresses_of_its_exchange_in_the_additional_section() {
    let r = ask(&root(), "SRI-NIC.ARPA.", RecordType::MX);
    assert_eq!(r.answer, ["SRI-NIC.ARPA. 86400 IN MX 0 SRI-NIC.ARPA."]);
    assert_eq!(
        r.additional,
        [
            "SRI-NIC.ARPA. 86400 IN A 26.0.0.73",
            "SRI-NIC.ARPA. 86400 IN A 10.0.0.51"
        ]
    );
    assert_eq!(r.authority, Vec::<String>::new());
}

#[test]
fn s6_2_4_a_name_without_the_type_asked_is_no_data_with_the_soa() {
    // The RFC leaves the authority section empty; RFC 2308 §2.2 puts the SOA there.
    let r = ask(&root(), "SRI-NIC.ARPA.", RecordType::NS);
    assert!(r.aa);
    assert_eq!(r.rcode, Rcode::NOERROR);
    assert_eq!(r.answer, Vec::<String>::new());
    assert_eq!(r.authority, [SOA_ROOT]);
}

#[test]
fn s6_2_5_a_name_that_is_not_there_is_nxdomain_with_the_soa() {
    let r = ask(&root(), "SIR-NIC.ARPA.", RecordType::A);
    assert!(r.aa);
    assert_eq!(r.rcode, Rcode::NXDOMAIN);
    assert_eq!((r.answer, r.authority), (vec![], vec![SOA_ROOT.to_owned()]));
}

#[test]
fn s6_2_6_a_name_below_a_delegation_is_a_referral_with_glue() {
    let r = ask(&root(), "BRL.MIL.", RecordType::A);
    assert!(!r.aa);
    assert_eq!(r.rcode, Rcode::NOERROR);
    assert_eq!(r.answer, Vec::<String>::new());
    assert_eq!(
        r.authority,
        [
            "MIL. 86400 IN NS SRI-NIC.ARPA.",
            "MIL. 86400 IN NS A.ISI.EDU."
        ]
    );
    // The addresses the zone has, the one below another cut included: A.ISI.EDU. is glue of EDU.
    assert_eq!(
        r.additional,
        [
            "SRI-NIC.ARPA. 86400 IN A 26.0.0.73",
            "SRI-NIC.ARPA. 86400 IN A 10.0.0.51",
            "A.ISI.EDU. 86400 IN A 26.3.0.103",
        ]
    );
    // None of it is in the delegated domain: no glue is required.
    assert_eq!(r.required_glue, 0);
}

#[test]
fn s6_2_7_a_cname_is_followed_to_where_the_zone_ends() {
    // C.ISI.EDU. is below the cut of EDU.: the answer is the CNAME, and a referral for the rest.
    let r = ask(&root(), "USC-ISIC.ARPA.", RecordType::A);
    assert!(r.aa);
    assert_eq!(r.answer, ["USC-ISIC.ARPA. 86400 IN CNAME C.ISI.EDU."]);
    assert_eq!(
        r.authority,
        [
            "EDU. 86400 IN NS SRI-NIC.ARPA.",
            "EDU. 86400 IN NS C.ISI.EDU."
        ]
    );
    // C.ISI.EDU. is in the delegated domain: its address is required in the referral (RFC 9471 §2.1).
    assert_eq!(r.required_glue, 1);
    assert_eq!(r.additional[0], "C.ISI.EDU. 86400 IN A 10.0.0.52");
}

#[test]
fn s6_2_8_a_cname_asked_for_is_not_followed() {
    let r = ask(&root(), "USC-ISIC.ARPA.", RecordType::CNAME);
    assert_eq!(r.answer, ["USC-ISIC.ARPA. 86400 IN CNAME C.ISI.EDU."]);
    assert_eq!((r.authority, r.additional), (vec![], vec![]));
}

// --- RFC 1034 §4.3.2, RFC 1035 §4.1.1 ---

/// RFC 6604 §2.1: AA is the first owner's and the RCODE the last name's: a chain from an authoritative name that
/// ends in a referral is AA, NOERROR, with the cut's NS in the authority.
#[test]
fn rfc6604_s2_1_a_chain_that_ends_in_a_referral_is_authoritative() {
    let zone = example("a CNAME x.sub\nsub NS ns.other.\n");
    let r = ask(&zone, "a.example.", RecordType::A);
    assert_eq!((r.rcode, r.aa), (Rcode::NOERROR, true));
    assert_eq!(r.answer.len(), 1);
    assert_eq!(r.authority.len(), 1);
    let r = ask(&zone, "a.example.", RecordType::CNAME);
    assert_eq!(
        (r.rcode, r.aa, r.authority.len()),
        (Rcode::NOERROR, true, 0)
    );
    // The name asked is below the cut itself: not authoritative.
    assert!(!ask(&zone, "x.sub.example.", RecordType::A).aa);
}

#[test]
fn s4_3_2_a_name_outside_the_zone_or_of_another_class_is_refused() {
    let zone = example("");
    for (name, class) in [
        ("other.", Class::IN),
        ("example.com.", Class::IN),
        ("www.example.", Class::CH),
    ] {
        let r = ask_class(&zone, name, RecordType::A, class);
        assert_eq!(r.rcode, Rcode::REFUSED, "{name}");
        assert!(!r.aa);
        assert_eq!((r.answer, r.authority), (vec![], vec![]));
    }
}

#[test]
fn s3_2_5_class_any_asks_every_class() {
    let r = ask_class(&example(""), "ns.example.", RecordType::A, Class::ANY);
    assert_eq!(r.answer, ["ns.example. 3600 IN A 192.0.2.1"]);
}

#[test]
fn s4_3_2_the_owner_is_the_name_as_asked_whatever_its_case() {
    let r = ask(&example(""), "NS.Example.", RecordType::A);
    assert_eq!(r.answer, ["NS.Example. 3600 IN A 192.0.2.1"]);
}

#[test]
fn s4_3_2_the_apex_ns_is_not_in_the_authority_of_a_positive_answer() {
    // NSD adds it, Knot does not (D203); dedensd follows Knot.
    let r = ask(&example(""), "ns.example.", RecordType::A);
    assert_eq!((r.authority, r.additional), (vec![], vec![]));
}

// --- RFC 2308 §3, §5 ---

#[test]
fn s5_a_negative_answer_has_the_soa_with_the_lower_of_its_ttl_and_minimum() {
    // TTL 2 h, MINIMUM 10 min.
    let r = ask(&example(""), "ns.example.", RecordType::MX);
    assert_eq!(
        r.authority,
        ["example. 600 IN SOA ns.example. hostmaster.example. 1 86400 7200 2419200 600"]
    );
    let zone = zone(
        "example.",
        "$TTL 1h\n@ 5m SOA ns hostmaster 1 1d 2h 4w 10m\n@ NS ns\nns A 192.0.2.1\n",
    );
    let r = ask(&zone, "nothing.example.", RecordType::A);
    assert_eq!(r.rcode, Rcode::NXDOMAIN);
    assert_eq!(
        r.authority,
        ["example. 300 IN SOA ns.example. hostmaster.example. 1 86400 7200 2419200 600"]
    );
}

// --- RFC 8482 §4.2 ---

#[test]
fn s4_2_any_is_the_rrset_of_the_lowest_type() {
    let zone = example("a A 192.0.2.2\na TXT \"x\"\na MX 10 ns\n");
    let r = ask(&zone, "a.example.", RecordType::ANY);
    assert_eq!(r.answer, ["a.example. 3600 IN A 192.0.2.2"]);
}

// --- RFC 1034 §3.6.2, §4.3.2 step 3a ---

#[test]
fn s4_3_2_a_cname_chain_in_the_zone_ends_with_the_data() {
    let zone = example("a CNAME b\nb CNAME c\nc A 192.0.2.3\n");
    let r = ask(&zone, "a.example.", RecordType::A);
    assert!(r.aa);
    assert_eq!(
        r.answer,
        [
            "a.example. 3600 IN CNAME b.example.",
            "b.example. 3600 IN CNAME c.example.",
            "c.example. 3600 IN A 192.0.2.3",
        ]
    );
}

#[test]
fn s4_3_2_a_cname_to_a_name_that_is_not_there_is_nxdomain_with_the_chain() {
    let zone = example("a CNAME gone\n");
    let r = ask(&zone, "a.example.", RecordType::A);
    assert_eq!(r.rcode, Rcode::NXDOMAIN);
    assert_eq!(r.answer, ["a.example. 3600 IN CNAME gone.example."]);
    assert_eq!(r.authority.len(), 1);
}

#[test]
fn s4_3_2_a_cname_out_of_the_zone_ends_the_chain_there() {
    let zone = example("a CNAME www.other.\n");
    let question = Question::new(dns("a.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(answer.chain.len(), 1);
    assert!(matches!(answer.end, End::Open { ref name } if *name == dns("www.other.")));
    assert_eq!(answer.rcode(), Rcode::NOERROR);
    assert!(answer.authoritative());
}

#[test]
fn s4_3_2_a_chain_is_followed_up_to_max_chain_links() {
    let mut text = String::new();
    for i in 0..=MAX_CHAIN + 1 {
        let _ = writeln!(text, "c{i} CNAME c{}", i + 1);
    }
    let _ = writeln!(text, "c{} A 192.0.2.9", MAX_CHAIN + 2);
    let zone = example(&text);
    let question = Question::new(dns("c0.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(answer.chain.len(), MAX_CHAIN);
    assert!(
        matches!(answer.end, End::Open { ref name } if *name == dns(&format!("c{MAX_CHAIN}.example.")))
    );
    // One link less than the bound is still answered.
    let question = Question::new(dns("c3.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(answer.chain.len(), 10);
    assert!(matches!(answer.end, End::Data { .. }));
    // The bound itself is answered: MAX_CHAIN links and the data after them.
    let question = Question::new(dns("c2.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(answer.chain.len(), MAX_CHAIN);
    assert!(matches!(answer.end, End::Data { .. }));
}

#[test]
fn s4_3_2_a_loop_of_aliases_is_shown_once() {
    let zone = example("a CNAME b\nb CNAME a\n");
    let r = ask(&zone, "a.example.", RecordType::A);
    assert_eq!(
        r.answer,
        [
            "a.example. 3600 IN CNAME b.example.",
            "b.example. 3600 IN CNAME a.example."
        ]
    );
}

// --- RFC 4592 §2.2.1, §3 ---

const WILDCARDS: &str = "$ORIGIN example.
$TTL 1h
@ SOA ns.example.net. hostmaster.example.net. 1 1d 2h 4w 1h
@ NS ns.example.com.
@ NS ns.example.net.
* TXT \"this is a wildcard\"
* MX 10 host1
sub.* TXT \"this is not a wildcard\"
host1 A 192.0.4.1
_ssh._tcp.host1 SRV 0 0 9 host1
_ssh._tcp.host2 SRV 0 0 9 host2
subdel NS ns.example.com.
subdel NS ns.example.net.
";

fn wildcards() -> Zone {
    zone("example.", WILDCARDS)
}

#[test]
fn s2_2_1_a_wildcard_answers_for_a_name_that_is_not_there() {
    let r = ask(&wildcards(), "host3.example.", RecordType::MX);
    assert!(r.aa);
    assert_eq!(r.answer, ["host3.example. 3600 IN MX 10 host1.example."]);
    assert_eq!(r.additional, ["host1.example. 3600 IN A 192.0.4.1"]);
}

#[test]
fn s2_2_1_a_wildcard_without_the_type_is_no_data() {
    let r = ask(&wildcards(), "host3.example.", RecordType::A);
    assert_eq!(r.rcode, Rcode::NOERROR);
    assert_eq!(r.answer, Vec::<String>::new());
    assert_eq!(r.authority.len(), 1);
}

#[test]
fn s2_2_1_a_wildcard_answers_for_a_name_with_labels_that_are_not_there() {
    let r = ask(&wildcards(), "foo.bar.example.", RecordType::TXT);
    assert_eq!(
        r.answer,
        ["foo.bar.example. 3600 IN TXT \"this is a wildcard\""]
    );
}

#[test]
fn s2_2_1_a_wildcard_answers_in_the_case_asked() {
    let r = ask(&wildcards(), "Foo.BAR.example.", RecordType::TXT);
    assert_eq!(
        r.answer,
        ["Foo.BAR.example. 3600 IN TXT \"this is a wildcard\""]
    );
}

#[test]
fn s2_2_1_where_a_wildcard_does_not_answer() {
    let zone = wildcards();
    // host1.example. exists.
    let r = ask(&zone, "host1.example.", RecordType::MX);
    assert_eq!((r.rcode, r.answer.len()), (Rcode::NOERROR, 0));
    // sub.*.example. exists.
    let r = ask(&zone, "sub.*.example.", RecordType::MX);
    assert_eq!((r.rcode, r.answer.len()), (Rcode::NOERROR, 0));
    // _tcp.host1.example. exists, without data: an empty non-terminal.
    let r = ask(&zone, "_tcp.host1.example.", RecordType::SRV);
    assert_eq!((r.rcode, r.answer.len()), (Rcode::NOERROR, 0));
    assert_eq!(r.authority.len(), 1);
    let r = ask(&zone, "_telnet._tcp.host1.example.", RecordType::SRV);
    assert_eq!((r.rcode, r.answer.len()), (Rcode::NXDOMAIN, 0));
    // subdel.example. is a zone cut.
    let r = ask(&zone, "host.subdel.example.", RecordType::A);
    assert_eq!((r.rcode, r.aa), (Rcode::NOERROR, false));
    assert_eq!(
        r.authority,
        [
            "subdel.example. 3600 IN NS ns.example.com.",
            "subdel.example. 3600 IN NS ns.example.net."
        ]
    );
    // *.example. exists: a wildcard blocks itself.
    let r = ask(&zone, "ghost.*.example.", RecordType::MX);
    assert_eq!((r.rcode, r.answer.len()), (Rcode::NXDOMAIN, 0));
}

#[test]
fn s3_3_1_the_wildcard_and_its_closest_encloser_are_in_the_answer() {
    let zone = wildcards();
    let question = Question::new(dns("foo.bar.example."), RecordType::TXT);
    let answer = zone.answer(&question);
    let End::Data { at, .. } = &answer.end else {
        unreachable!("data");
    };
    let dedens_zone::Match::Wildcard { source, encloser } = at else {
        unreachable!("a wildcard");
    };
    assert_eq!(*source.name, dns("*.example."));
    assert_eq!(*encloser.name, dns("example."));
    // A name that is not there, with no wildcard: the encloser is what a proof needs.
    let question = Question::new(dns("a.b.host1.example."), RecordType::A);
    let answer = zone.answer(&question);
    let End::NxDomain { encloser, .. } = &answer.end else {
        unreachable!("nxdomain");
    };
    assert_eq!(*encloser.name, dns("host1.example."));
}

// --- RFC 6672 §2.2, §3 ---

#[test]
fn s2_2_a_dname_substitutes_its_target_for_its_owner() {
    // The table of §2.2: the owner is example.com., the target example.net.
    let zone = zone(
        "example.com.",
        &format!(
            "$TTL 1h\n@ SOA ns hostmaster 1 1d 2h 4w 1h\n@ NS ns\nns A 192.0.2.1\n{}",
            dname("@", "example.net.")
        ),
    );
    let r = ask(&zone, "a.example.com.", RecordType::A);
    assert!(r.aa);
    assert_eq!(r.rcode, Rcode::NOERROR);
    assert_eq!(
        r.answer,
        [
            dname_text("example.com.", "example.net.").as_str(),
            "a.example.com. 3600 IN CNAME a.example.net."
        ]
    );
    let r = ask(&zone, "a.b.example.com.", RecordType::A);
    assert_eq!(
        r.answer[1],
        "a.b.example.com. 3600 IN CNAME a.b.example.net."
    );
    // The owner itself is not substituted: [0] of the table is its own data.
    let r = ask(&zone, "example.com.", RecordType::A);
    assert_eq!(r.answer, Vec::<String>::new());
    assert_eq!(r.authority.len(), 1);
    let r = ask(&zone, "example.com.", RecordType::DNAME);
    assert_eq!(r.answer, [dname_text("example.com.", "example.net.")]);
    // A name outside is refused.
    let r = ask(&zone, "com.", RecordType::A);
    assert_eq!(r.rcode, Rcode::REFUSED);
}

#[test]
fn s2_2_only_whole_labels_are_replaced() {
    let zone = example(&dname("b", "other."));
    // ab.example. is not below b.example.: no substitution, NXDOMAIN.
    let r = ask(&zone, "ab.example.", RecordType::A);
    assert_eq!(r.rcode, Rcode::NXDOMAIN);
    let r = ask(&zone, "a.b.example.", RecordType::A);
    assert_eq!(r.answer[1], "a.b.example. 3600 IN CNAME a.other.");
}

#[test]
fn s2_2_a_name_the_zone_holds_below_a_dname_is_redirected_not_referred() {
    // RFC 6672 §2.4: data below a DNAME owner is occluded; the load warns and keeps it, the answer never gives it.
    let zone = example(&format!("{}x.d A 192.0.2.5\n", dname("d", "other.")));
    let r = ask(&zone, "x.d.example.", RecordType::A);
    assert!(r.aa);
    assert_eq!(r.answer[1], "x.d.example. 3600 IN CNAME x.other.");
    assert_eq!(r.authority, Vec::<String>::new());
}

#[test]
fn s2_2_a_longer_target_makes_a_longer_name() {
    let zone = example(&dname("@", "y.net."));
    let r = ask(&zone, "a.example.", RecordType::A);
    assert_eq!(r.answer[1], "a.example. 3600 IN CNAME a.y.net.");
}

#[test]
fn s2_2_a_dname_that_leads_into_the_zone_is_followed() {
    // x.example. is the DNAME's owner, its target is inside the zone: the data is found there.
    let zone = example(&format!("{}t A 192.0.2.7\n", dname("x", "t.example.")));
    let r = ask(&zone, "x.example.", RecordType::A);
    assert_eq!(
        r.answer,
        Vec::<String>::new(),
        "the owner is not substituted"
    );
    let question = Question::new(dns("sub.x.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(
        answer.chain.len(),
        1,
        "the DNAME and its CNAME are one link"
    );
    assert!(matches!(answer.chain[0], Link::Dname { .. }));
    // sub.t.example. is not there: NXDOMAIN after the chain (RFC 6604 §3).
    assert_eq!(answer.rcode(), Rcode::NXDOMAIN);
    let r = ask(&zone, "sub.x.example.", RecordType::A);
    assert_eq!(r.answer.len(), 2);
    assert_eq!(r.rcode, Rcode::NXDOMAIN);
}

#[test]
fn s2_2_a_dname_that_leads_to_itself_is_a_loop_shown_once() {
    // 'cyc' of the table: the owner is the apex and so is the target.
    let zone = example(&dname("@", "example."));
    let question = Question::new(dns("cyc.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(answer.chain.len(), 1);
    assert!(matches!(answer.end, End::Open { ref name } if *name == dns("cyc.example.")));
}

#[test]
fn s3_2_a_cname_asked_below_a_dname_is_answered_by_the_synthesised_one() {
    let zone = example(&dname("d", "other."));
    let question = Question::new(dns("a.d.example."), RecordType::CNAME);
    let answer = zone.answer(&question);
    assert!(matches!(answer.end, End::Synthesized));
    let r = ask(&zone, "a.d.example.", RecordType::CNAME);
    assert_eq!(
        r.answer,
        [
            dname_text("d.example.", "other.").as_str(),
            "a.d.example. 3600 IN CNAME a.other."
        ]
    );
}

#[test]
fn s2_2_a_name_made_too_long_is_yxdomain_with_the_dname() {
    // A target of 254 bytes: one more label makes the name 256.
    let target = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".")
        + ".";
    let zone = example(&dname("d", &target));
    let r = ask(&zone, "x.d.example.", RecordType::A);
    assert_eq!(r.rcode, Rcode::YXDOMAIN);
    assert!(r.aa);
    assert_eq!(r.answer, [dname_text("d.example.", &target)]);
    assert_eq!(r.authority, Vec::<String>::new());
    // A name that fits is substituted.
    let r = ask(&zone, "d.example.", RecordType::DNAME);
    assert_eq!(r.rcode, Rcode::NOERROR);
}

#[test]
fn s6_1_a_dname_beside_other_data_at_its_owner_does_not_redirect_it() {
    // RFC 6672 §6.1: the MX at the owner is its own.
    let zone = example(&format!(
        "{}f MX 10 ns\n",
        dname("f", "frobozz-division.acme.example.com.")
    ));
    let r = ask(&zone, "f.example.", RecordType::MX);
    assert_eq!(r.answer, ["f.example. 3600 IN MX 10 ns.example."]);
    let r = ask(&zone, "www.f.example.", RecordType::A);
    assert_eq!(
        r.answer[1],
        "www.f.example. 3600 IN CNAME www.frobozz-division.acme.example.com."
    );
}

#[test]
fn s6_2_a_dname_delegates_a_shorter_prefix() {
    let text = format!(
        "$TTL 1h\n@ SOA ns hostmaster 1 1d 2h 4w 1h\n@ NS ns\nns A 192.0.2.1\n8/22 NS ns.slash-22-holder.example.com.\n{}",
        dname("8", "8.8/22.0.192.in-addr.arpa.")
    );
    let zone = zone("0.192.in-addr.arpa.", &text);
    let r = ask(&zone, "33.8.0.192.in-addr.arpa.", RecordType::PTR);
    assert_eq!(
        r.answer[1],
        "33.8.0.192.in-addr.arpa. 3600 IN CNAME 33.8.8/22.0.192.in-addr.arpa."
    );
    // The CNAME leads to the delegation: a referral to the holder.
    assert_eq!(
        r.authority,
        ["8/22.0.192.in-addr.arpa. 3600 IN NS ns.slash-22-holder.example.com."]
    );
}

// --- RFC 4035 §3.1.4.1: DS at a delegation ---

#[test]
fn s3_1_4_1_a_ds_at_a_delegation_is_answered_from_the_parent() {
    let zone = example(
        "sub NS ns.other.\nsub DS 12345 8 2 49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD\n",
    );
    let r = ask(&zone, "sub.example.", RecordType::DS);
    assert!(r.aa);
    assert_eq!(r.answer.len(), 1);
    // No DS: no data, from the parent, with AA and the SOA (RFC 4035 §3.1.4.1).
    let zone = example("sub NS ns.other.\n");
    let r = ask(&zone, "sub.example.", RecordType::DS);
    assert!(r.aa);
    assert_eq!(r.rcode, Rcode::NOERROR);
    assert_eq!((r.answer.len(), r.authority.len()), (0, 1));
    // Another type is a referral.
    let r = ask(&zone, "sub.example.", RecordType::A);
    assert!(!r.aa);
    assert_eq!(r.authority, ["sub.example. 3600 IN NS ns.other."]);
}

// --- RFC 9471 §2, §3.1 ---

const GLUE: &str = "sub NS ns1.sub
sub NS ns.other.example.
sub NS ns2.sub
ns1.sub A 192.0.2.11
ns1.sub AAAA 2001:db8::11
ns2.sub A 192.0.2.12
";

#[test]
fn s2_a_referral_has_glue_in_the_delegated_domain_first_and_requires_it() {
    let zone = example(&format!("{GLUE}ns.other A 192.0.2.20\n"));
    let r = ask(&zone, "www.sub.example.", RecordType::A);
    assert!(!r.aa);
    assert_eq!(
        r.additional,
        [
            "ns1.sub.example. 3600 IN A 192.0.2.11",
            "ns1.sub.example. 3600 IN AAAA 2001:db8::11",
            "ns2.sub.example. 3600 IN A 192.0.2.12",
            "ns.other.example. 3600 IN A 192.0.2.20",
        ]
    );
    assert_eq!(r.required_glue, 3);
}

#[test]
fn s3_1_a_referral_whose_glue_does_not_fit_is_truncated_and_sibling_glue_is_dropped_whole() {
    let zone = example(&format!("{GLUE}ns.other A 192.0.2.20\n"));
    let question = Question::new(dns("www.sub.example."), RecordType::A);
    let answer = zone.answer(&question);
    let mut message = Message {
        header: Header {
            flags: Flags::QR,
            ..Header::default()
        },
        questions: vec![question.clone()],
        ..Message::default()
    };
    let glue = answer.fill(&zone, &mut message, MAX_MESSAGE_LEN);
    let full = message.to_vec().expect("encodes");
    let mut buf = vec![0; 4096];
    // Everything fits: no TC.
    let len = glue.encode(&message, &mut buf).expect("encodes");
    assert_eq!(&buf[..len], full.as_slice());
    assert!(
        !Message::decode(&buf[..len])
            .expect("decodes")
            .message
            .header
            .flags
            .contains(Flags::TC)
    );
    // Room for the three required records and the optional one's absence: not truncated.
    let (mut fitting, mut cut) = (0, 0);
    for limit in full.len() - 64..=full.len() {
        let mut buf = vec![0; limit];
        let len = glue.encode(&message, &mut buf).expect("encodes");
        let decoded = Message::decode(&buf[..len]).expect("decodes").message;
        let kept = decoded.additional.len();
        let tc = decoded.header.flags.contains(Flags::TC);
        // TC exactly when a required record is gone (RFC 9471 §3.1).
        assert_eq!(tc, kept < glue.required(), "limit {limit}: kept {kept}");
        if !tc && kept == 3 {
            fitting += 1;
        }
        if tc && kept < 3 {
            cut += 1;
        }
    }
    assert!(fitting > 0, "a size that holds the required glue only");
    assert!(cut > 0, "a size that loses required glue");
    // Too small for the authority: the answer is cut and TC is set by the encoder.
    let mut buf = vec![0; 60];
    let len = glue.encode(&message, &mut buf).expect("encodes");
    let decoded = Message::decode(&buf[..len]).expect("decodes").message;
    assert!(decoded.header.flags.contains(Flags::TC));
}

#[test]
fn s2_glue_is_not_added_for_a_cname_target() {
    // RFC 2181 §10.3: an alias is not an NS or MX target; nothing is resolved for it.
    let zone = example("a MX 10 alias\nalias CNAME ns\n");
    let r = ask(&zone, "a.example.", RecordType::MX);
    assert_eq!(r.additional, Vec::<String>::new());
}

#[test]
fn s2_the_additional_section_of_an_ns_answer_has_the_addresses_of_the_servers() {
    let r = ask(&example(""), "example.", RecordType::NS);
    assert_eq!(r.answer, ["example. 3600 IN NS ns.example."]);
    assert_eq!(r.additional, ["ns.example. 3600 IN A 192.0.2.1"]);
}

// --- RFC 5155 §7.2 ---

#[test]
fn s7_2_a_name_with_only_nsec3_records_is_not_there() {
    let zone = zone("example.", &zone_file("rfc5155_appendix_a.zone"));
    let r = ask(
        &zone,
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
        RecordType::NSEC3,
    );
    assert_eq!(r.rcode, Rcode::NXDOMAIN);
}

#[test]
fn s7_2_the_closest_encloser_of_a_name_below_one_with_only_nsec3_records_is_that_name() {
    // The ancestor is a node (D204), and a name asked below it has it as the closest encloser: only the name
    // asked itself is not there for its NSEC3 records alone.
    let zone = zone("example.", &zone_file("rfc5155_appendix_a.zone"));
    let question = Question::new(
        dns("x.0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example."),
        RecordType::A,
    );
    let answer = zone.answer(&question);
    let End::NxDomain { encloser, .. } = &answer.end else {
        unreachable!("nxdomain");
    };
    assert_eq!(
        *encloser.name,
        dns("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.")
    );
}

#[test]
fn rdata_of_a_cname_is_read_in_place() {
    // The name an alias leads to is the RDATA's own, not a copy.
    let zone = example("a CNAME b\n");
    let node = zone.node(&dns("a.example.")).expect("a");
    let rrset = node.rrset(RecordType::CNAME).expect("CNAME");
    let RData::Cname(target) = rrset.rdatas()[0].data() else {
        unreachable!("a CNAME");
    };
    assert_eq!(target, dns("b.example."));
}

// --- Names the zone holds only below, wildcards of other kinds ---

#[test]
fn s4_9_a_wildcard_that_is_an_empty_non_terminal_is_no_data() {
    // `*.foo.example.` holds no record, only `a.*.foo.example.` does: it exists, and answers nothing.
    let zone = example("a.*.foo TXT x\n");
    let r = ask(&zone, "x.foo.example.", RecordType::TXT);
    assert_eq!(r.rcode, Rcode::NOERROR);
    assert!(r.aa);
    assert_eq!((r.answer.len(), r.authority.len()), (0, 1));
}

#[test]
fn s4_3_3_a_wildcard_cname_is_followed_from_the_name_asked() {
    let zone = example("* CNAME target\ntarget A 192.0.2.9\n");
    let r = ask(&zone, "foo.example.", RecordType::A);
    assert_eq!(
        r.answer,
        [
            "foo.example. 3600 IN CNAME target.example.",
            "target.example. 3600 IN A 192.0.2.9"
        ]
    );
}

#[test]
fn s4_3_3_a_wildcard_cname_that_leads_back_to_the_wildcard_ends_the_loop() {
    // `x.example.` is not there either: the wildcard answers it again.
    let zone = example("* CNAME x\n");
    let question = Question::new(dns("foo.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(answer.chain.len(), 2);
    assert!(matches!(answer.end, End::Open { ref name } if *name == dns("x.example.")));
    assert_eq!(answer.rcode(), Rcode::NOERROR);
}

#[test]
fn s4_2_a_wildcard_that_is_a_delegation_point_refers() {
    // RFC 4592 §4.2 leaves it open; as Knot does, D206.
    let zone = example("* NS ns.other.\n");
    for rtype in [RecordType::A, RecordType::NS] {
        let r = ask(&zone, "foo.example.", rtype);
        assert!(!r.aa, "{rtype:?}");
        assert_eq!(r.answer, Vec::<String>::new());
        assert_eq!(r.authority, ["*.example. 3600 IN NS ns.other."]);
    }
    // A DS is the parent's data, as at any delegation point: here none.
    let r = ask(&zone, "foo.example.", RecordType::DS);
    assert!(r.aa);
    assert_eq!((r.answer.len(), r.authority.len()), (0, 1));
}

#[test]
fn s3_1_4_1_a_ds_below_a_delegation_is_a_referral() {
    let zone = example("sub NS ns.other.\nwww.sub A 192.0.2.8\n");
    for name in ["www.sub.example.", "not.there.sub.example."] {
        let r = ask(&zone, name, RecordType::DS);
        assert!(!r.aa, "{name}");
        assert_eq!(r.authority, ["sub.example. 3600 IN NS ns.other."]);
    }
}

#[test]
fn s4_2_1_any_at_a_delegation_point_is_a_referral() {
    let zone = example(
        "sub NS ns.other.\nsub DS 12345 8 2 49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD\n",
    );
    let r = ask(&zone, "sub.example.", RecordType::ANY);
    assert!(!r.aa);
    assert_eq!(r.answer, Vec::<String>::new());
    assert_eq!(r.authority, ["sub.example. 3600 IN NS ns.other."]);
}

// --- DNAME chains that grow ---

#[test]
fn s3_1_a_dname_whose_target_is_below_its_owner_grows_the_name_until_the_chain_ends() {
    let zone = example(&dname("d", "b.d.example."));
    let question = Question::new(dns("x.d.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(answer.chain.len(), MAX_CHAIN);
    assert!(matches!(answer.end, End::Open { .. }));
    assert_eq!(answer.rcode(), Rcode::NOERROR);
    assert!(answer.authoritative());
}

#[test]
fn s2_2_a_dname_that_grows_the_name_past_255_bytes_is_yxdomain_before_the_bound() {
    // Each link adds a label of 30 bytes to a name of 12: the ninth makes 282.
    let label = "b".repeat(29);
    let zone = example(&dname("d", &format!("{label}.d.example.")));
    let question = Question::new(dns("x.d.example."), RecordType::A);
    let answer = zone.answer(&question);
    assert_eq!(answer.chain.len(), 8);
    assert!(matches!(answer.end, End::YxDomain { .. }));
    assert_eq!(answer.rcode(), Rcode::YXDOMAIN);
}

// --- A name of 122 labels, the longest the zone takes ---

#[test]
fn s4_3_2_a_name_with_the_most_labels_is_found_from_the_apex_down() {
    let long = format!("{}example.", "x.".repeat(122));
    let zone = example("a.a MX 10 ns\nsub NS ns.other.\n");
    // Not there: the encloser is the apex.
    let question = Question::new(dns(&long), RecordType::A);
    let answer = zone.answer(&question);
    let End::NxDomain { encloser, .. } = &answer.end else {
        unreachable!("nxdomain");
    };
    assert_eq!(*encloser.name, dns("example."));
    // Below a delegation: its referral, whatever the length.
    let r = ask(
        &zone,
        &format!("{}sub.example.", "x.".repeat(120)),
        RecordType::A,
    );
    assert_eq!(r.authority, ["sub.example. 3600 IN NS ns.other."]);
    // Below a name that is there.
    let r = ask(
        &zone,
        &format!("{}a.a.example.", "x.".repeat(118)),
        RecordType::A,
    );
    assert_eq!(r.rcode, Rcode::NXDOMAIN);
}

// --- The additional section of an answer: authoritative names and glue, not below a DNAME ---

#[test]
fn s2_4_an_answer_has_the_glue_below_a_delegation_point_but_no_address_below_a_dname() {
    // The first cut on the way down decides: glue below a delegation even where a DNAME is further down,
    // nothing below a DNAME even where a delegation is further down. An address at the delegation point itself is
    // glue too, being at a zone cut (RFC 9499), as Knot gives it.
    let zone = example(&format!(
        "{}x.d A 192.0.2.7\ng.d NS ns.other.\nh.g.d A 192.0.2.9\n\
         sub NS ns.other.\nh.sub A 192.0.2.8\nsub A 192.0.2.10\n{}y.e.sub A 192.0.2.11\n\
         a MX 10 x.d\nf MX 10 h.g.d\nb MX 10 h.sub\np MX 10 sub\nq MX 10 y.e.sub\nc MX 10 ns\n",
        dname("d", "other."),
        dname("e.sub", "other."),
    ));
    for name in ["a.example.", "f.example."] {
        let r = ask(&zone, name, RecordType::MX);
        assert_eq!(r.answer.len(), 1, "{name}");
        assert_eq!(r.additional, Vec::<String>::new(), "{name}");
        assert_eq!(r.required_glue, 0, "{name}");
    }
    for (name, address) in [
        ("b.example.", "h.sub.example. 3600 IN A 192.0.2.8"),
        ("p.example.", "sub.example. 3600 IN A 192.0.2.10"),
        ("q.example.", "y.e.sub.example. 3600 IN A 192.0.2.11"),
        ("c.example.", "ns.example. 3600 IN A 192.0.2.1"),
    ] {
        let r = ask(&zone, name, RecordType::MX);
        assert_eq!(r.additional, [address], "{name}");
        // Glue in an answer is optional: TC is never set for it.
        assert_eq!(r.required_glue, 0, "{name}");
    }
}

#[test]
fn s2_4_a_referral_takes_no_address_from_below_a_dname_either() {
    // `x.d` is below a DNAME: the referral's optional addresses leave it out, as an answer does; a sibling's stay.
    let zone = example(&format!(
        "{}x.d A 192.0.2.7\nsub NS ns.sub\nsub NS x.d.example.\nsub NS ns.other.example.\n\
         ns.sub A 192.0.2.11\nns.other A 192.0.2.20\n",
        dname("d", "other.")
    ));
    let r = ask(&zone, "www.sub.example.", RecordType::A);
    assert_eq!(
        r.additional,
        [
            "ns.sub.example. 3600 IN A 192.0.2.11",
            "ns.other.example. 3600 IN A 192.0.2.20",
        ]
    );
    assert_eq!(r.required_glue, 1);
}

#[test]
fn s2_a_host_twice_in_an_rrset_has_its_addresses_once() {
    let r = ask(
        &example("m MX 10 ns\nm MX 20 ns\n"),
        "m.example.",
        RecordType::MX,
    );
    assert_eq!(r.answer.len(), 2);
    assert_eq!(r.additional, ["ns.example. 3600 IN A 192.0.2.1"]);
}

// --- The additional section is collected up to what the response can hold ---

/// A zone with `mx MX` of 100 hosts, each with 100 A and 100 AAAA records: 20 000 addresses, the most the default
/// limits let one `RRset` of hosts reach.
fn many_addresses() -> Zone {
    let mut text = String::new();
    for host in 0..100 {
        writeln!(text, "mx MX 10 h{host}").expect("writes");
        for address in 0..100 {
            writeln!(text, "h{host} A 192.0.2.{address}").expect("writes");
            writeln!(text, "h{host} AAAA 2001:db8::{address:x}").expect("writes");
        }
    }
    example(&text)
}

/// How many records the additional section has when `limit` is what `fill` is given for the MX of `mx.example.`.
fn collected(zone: &Zone, limit: usize) -> usize {
    let question = Question::new(dns("mx.example."), RecordType::MX);
    let answer = zone.answer(&question);
    let mut message = Message::default();
    answer.fill(zone, &mut message, limit);
    assert_eq!(message.answer.len(), 100);
    message.additional.len()
}

#[test]
fn s2_the_addresses_of_the_hosts_are_collected_only_up_to_the_size_of_the_response() {
    let zone = many_addresses();
    // A host's A and AAAA records take 100 × (12 + 4) + 100 × (12 + 16) = 4 400 bytes at the least. Collecting
    // stops once the records taken go over the limit, between hosts.
    assert_eq!(collected(&zone, 1232), 200);
    assert_eq!(collected(&zone, 4399), 200);
    assert_eq!(collected(&zone, 4400), 400);
    // 15 hosts take 66 000 bytes: the first number of whole hosts over 65 535.
    assert_eq!(collected(&zone, MAX_MESSAGE_LEN), 3000);
}
