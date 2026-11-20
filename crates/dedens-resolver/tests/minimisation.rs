//! QNAME minimisation (D198) on the minimised resolutions of `testdata/recursion/minimised/`, each server answering
//! as captured through `Authorities`: RFC 9156 §2 (each zone asked the name one label below it, type A), §2.3 (a
//! long name's questions bounded), §3 (an empty non-terminal's NODATA leads on), RFC 8020 §2 (NXDOMAIN on a
//! minimised name ends a strict resolution), the relaxed fallback to the full name, the minimised questions within
//! `Limits` (D191) and shared as any other (D195).

use std::sync::Arc;
use std::time::Duration;

use dedens_proto::{Message, Name, Question, Rcode, RecordType};
use dedens_resolver::{
    Caches, Failure, Limit, Limits, Marks, Minimisation, Next, Query, Reply, Resolution, Resolved,
};
use dedens_testkit::recursion::{self, Authorities};

use crate::iteration::{
    Answered, Change, Sent, at, caches, captured, is, name, response, run, served, steer, to,
};
use crate::seeded::Seeded;

/// A minimised resolution of `testdata/recursion/minimised/`.
fn minimised(id: &str) -> recursion::Resolution {
    recursion::Resolution::read(&format!("minimised/{id}"))
}

/// A resolution of `name` and `rtype` at `capture`'s time.
fn start(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    (name, rtype): (&Name<'static>, RecordType),
    limits: Limits,
    minimisation: Minimisation,
) -> Resolution {
    let question = Question::new(name.clone(), rtype);
    Resolution::start(
        question,
        Arc::clone(caches),
        at(capture),
        limits,
        minimisation,
    )
    .expect("an IN question")
}

/// Resolves `capture`'s question, minimised as `minimisation` says, within `limits`, each captured response passed
/// through `change`.
fn resolve(
    capture: &recursion::Resolution,
    minimisation: Minimisation,
    limits: Limits,
    change: &Change<'_>,
) -> (Resolved, Vec<Sent>) {
    let caches = caches(false);
    let asked = (&capture.name, capture.rtype);
    let mut resolution = start(capture, &caches, asked, limits, minimisation);
    served(capture, &caches, &mut resolution, change)
}

/// The questions `capture` recorded, in order.
fn recorded(capture: &recursion::Resolution) -> Vec<Sent> {
    (capture.exchanges.iter())
        .map(|e| (e.zone.clone(), e.name.clone(), e.rtype))
        .collect()
}

/// Whether `response` answers `text`.
fn answers(response: &Message<'_>, text: &str) -> bool {
    response.questions.iter().any(|q| is(&q.name, text))
}

/// The response of jabber.org's server to `_tcp.jabber.org A`, an empty non-terminal, given `rcode`.
fn ent_answering(rcode: Rcode) -> impl Fn(&Name<'_>, &mut Message<'static>) {
    move |_, response| {
        if answers(response, "_tcp.jabber.org.") {
            response.set_rcode(rcode).expect("a 4-bit rcode");
        }
    }
}

#[test]
fn rfc9156_2_each_zone_is_asked_one_label_below_it() {
    let capture = minimised("ent");
    let (outcome, sent) = resolve(
        &capture,
        Minimisation::Relaxed,
        Limits::default(),
        &|_, _| {},
    );
    let Resolved::Answer { data, .. } = outcome else {
        panic!("{outcome:?} {sent:#?}");
    };
    assert_eq!(data.rrset.rtype(), RecordType::SRV);
    assert_eq!(sent, recorded(&capture));
    // The root's servers hear org, org's jabber.org, jabber.org's the empty non-terminal below it, then the name; the
    // lookup of a server name likewise.
    for (zone, name, rtype) in &sent {
        if (name, *rtype) != (&capture.name, capture.rtype) {
            assert_eq!(name.label_count(), zone.label_count() + 1, "{zone} {name}");
            assert_eq!(*rtype, RecordType::A, "{name}");
        }
    }
    let ent = (name("jabber.org."), name("_tcp.jabber.org."), RecordType::A);
    assert!(sent.contains(&ent), "{sent:?}");
}

#[test]
fn rfc9156_2_3_a_long_name_takes_ten_questions() {
    // 34 labels: one more label for each of the first 4 questions, then 5 more each, the 10th the full name, the
    // referrals to the zones on the way taken as they come.
    let capture = minimised("ip6");
    let (outcome, sent) = resolve(
        &capture,
        Minimisation::Relaxed,
        Limits::default(),
        &|_, _| {},
    );
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    assert_eq!(sent, recorded(&capture));
    let labels: Vec<usize> = (sent.iter())
        .filter(|(_, name, _)| capture.name.is_within(name))
        .map(|(_, name, _)| name.label_count())
        .collect();
    assert_eq!(labels, [1, 2, 3, 4, 9, 14, 19, 24, 29, 34]);
}

#[test]
fn rfc9156_2_3_eighteen_labels_take_the_example_questions() {
    // §2.3's example: 18 labels, 1, 1, 1, 1, 2, 2, 2, 2, 3 and 3 labels more a question. Changed: a name of 16
    // labels below jabber.org, whose server answers each question with its captured NODATA for `_tcp.jabber.org`.
    let capture = minimised("ent");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let nodata = response(&capture, "jabber.org.", "_tcp.jabber.org.");
    let server = |query: &Query| {
        let below = !is(&query.question.name, "jabber.org.");
        if is(&query.zone, "jabber.org.") && below {
            return Answered::Response(to(nodata.clone(), &query.question));
        }
        Answered::Response(captured(&authorities, query))
    };
    let long = name("p.o.n.m.l.k.j.i.h.g.f.e.d.c.b.a.jabber.org.");
    let asked = (&long, RecordType::A);
    let mut resolution = start(
        &capture,
        &caches,
        asked,
        Limits::default(),
        Minimisation::Relaxed,
    );
    let (outcome, sent) = run(&mut resolution, &server, at(&capture));
    assert!(matches!(outcome, Resolved::NoData { .. }), "{outcome:?}");
    let labels: Vec<usize> = (sent.iter())
        .filter(|(_, name, _)| long.is_within(name))
        .map(|(_, name, _)| name.label_count())
        .collect();
    assert_eq!(labels, [1, 2, 3, 4, 6, 8, 10, 12, 15, 18]);
}

#[test]
fn d198_minimised_questions_count_against_the_queries_bound() {
    let capture = minimised("ip6");
    let needed = capture.exchanges.len();
    let limits = Limits {
        queries: needed - 1,
        ..Limits::default()
    };
    let (outcome, sent) = resolve(&capture, Minimisation::Relaxed, limits, &|_, _| {});
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Queries)));
    assert_eq!(sent.len(), needed - 1);
}

#[test]
fn d198_relaxed_asks_the_full_name_after_nxdomain_for_an_empty_non_terminal() {
    // Changed: jabber.org's server answers NXDOMAIN for the empty non-terminal _tcp.jabber.org, as a server that
    // knows no empty non-terminal does (RFC 9156 §1); relaxed, the full name is asked, of the same server.
    let capture = minimised("ent");
    let change = ent_answering(Rcode::NXDOMAIN);
    let (outcome, sent) = resolve(&capture, Minimisation::Relaxed, Limits::default(), &change);
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    assert_eq!(sent, recorded(&capture));
}

#[test]
fn rfc8020_2_strict_ends_on_nxdomain_for_a_minimised_name() {
    // The same NXDOMAIN, strict: nothing exists below the name denied.
    let capture = minimised("ent");
    let change = ent_answering(Rcode::NXDOMAIN);
    let (outcome, sent) = resolve(&capture, Minimisation::Strict, Limits::default(), &change);
    assert!(matches!(outcome, Resolved::NxDomain { .. }), "{outcome:?}");
    let last = sent.last().expect("a question");
    assert_eq!(
        (&last.1, last.2),
        (&name("_tcp.jabber.org."), RecordType::A)
    );
}

#[test]
fn d198_relaxed_asks_the_full_name_after_a_refused_minimised_question() {
    // Changed: jabber.org's server refuses the empty non-terminal. Relaxed, the full name is asked of it; strict,
    // the minimised question goes to the next server, which the capture never asked.
    let capture = minimised("ent");
    let change = ent_answering(Rcode::REFUSED);
    let (relaxed, sent) = resolve(&capture, Minimisation::Relaxed, Limits::default(), &change);
    assert!(matches!(relaxed, Resolved::Answer { .. }), "{relaxed:?}");
    assert_eq!(sent, recorded(&capture));
    let (strict, sent) = resolve(&capture, Minimisation::Strict, Limits::default(), &change);
    assert!(matches!(strict, Resolved::Failed(_)), "{strict:?}");
    assert!(
        !sent.iter().any(|(_, name, _)| *name == capture.name),
        "{sent:?}"
    );
}

/// Resolves `ent`, the root's servers timing out on its minimised question `org. A`. Changed: they answer the full
/// name, and org's servers too, with the referral they gave to the minimised one.
fn root_timing_out(minimisation: Minimisation) -> (Resolved, Vec<Sent>) {
    let capture = minimised("ent");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let server = |query: &Query| {
        let asked = &query.question;
        if is(&query.zone, ".") && is(&asked.name, "org.") {
            return Answered::Timeout;
        }
        let referral = |zone, child: &str| {
            let below = asked.name.is_within(&name(child)) && asked.name != name(child);
            (is(&query.zone, zone) && below).then(|| to(response(&capture, zone, child), asked))
        };
        let changed = referral(".", "org.").or_else(|| referral("org.", "jabber.org."));
        Answered::Response(changed.unwrap_or_else(|| captured(&authorities, query)))
    };
    let asked = (&capture.name, capture.rtype);
    let mut resolution = start(&capture, &caches, asked, Limits::default(), minimisation);
    run(&mut resolution, &server, at(&capture))
}

#[test]
fn d198_relaxed_asks_the_full_name_after_3_timeouts() {
    let full = |sent: &[Sent]| {
        sent.iter()
            .filter(|(_, name, _)| is(name, "_xmpp-server._tcp.jabber.org."))
            .count()
    };
    let (outcome, sent) = root_timing_out(Minimisation::Relaxed);
    assert!(
        matches!(outcome, Resolved::Answer { .. }),
        "{outcome:?} {sent:?}"
    );
    let timeouts = sent.iter().filter(|(_, name, _)| is(name, "org."));
    assert_eq!(timeouts.count(), 3);
    // The full name to the root's, org's and jabber.org's servers.
    assert_eq!(full(&sent), 3, "{sent:?}");
    let (strict, sent) = root_timing_out(Minimisation::Strict);
    assert!(matches!(strict, Resolved::Failed(_)), "{strict:?}");
    assert_eq!(full(&sent), 0, "{sent:?}");
}

#[test]
fn d195_a_minimised_question_is_shared_with_the_name_it_asks() {
    // Minimised, _xmpp-server._tcp.jabber.org SRV asks what _tcp.jabber.org A asks, down to the latter: a server
    // sharing the queries keyed by server and question sends them once, and each resolution reads the reply to its
    // own end: the empty non-terminal's NODATA leads the first on and ends the second.
    let capture = minimised("ent");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let now = at(&capture);
    let ent = name("_tcp.jabber.org.");
    let mut srv = start(
        &capture,
        &caches,
        (&capture.name, capture.rtype),
        Limits::default(),
        Minimisation::Relaxed,
    );
    let mut a = start(
        &capture,
        &caches,
        (&ent, RecordType::A),
        Limits::default(),
        Minimisation::Relaxed,
    );
    let (mut srv_rng, mut a_rng) = (Seeded(0), Seeded(0));
    let mut shared = Vec::new();
    let outcome = loop {
        let query = match (srv.step(now, &mut srv_rng), a.step(now, &mut a_rng)) {
            (Next::Send(sent), Next::Send(waiting))
                if (sent.server, &sent.question) == (waiting.server, &waiting.question) =>
            {
                sent.clone()
            }
            (_, Next::Done(outcome)) => break outcome.clone(),
            (srv_next, a_next) => panic!("not shared: {srv_next:?} {a_next:?}"),
        };
        let response = captured(&authorities, &query);
        let reply = || Reply::Response {
            message: &response,
            seen: Marks::default(),
            rtt: Some(Duration::from_millis(20)),
        };
        srv.receive(reply(), now);
        a.receive_shared(reply(), now);
        shared.push(query.question.name.to_string());
    };
    assert!(matches!(outcome, Resolved::NoData { .. }), "{outcome:?}");
    assert!(shared.contains(&ent.to_string()), "{shared:?}");
    let Next::Send(next) = srv.step(now, &mut srv_rng) else {
        panic!("a query");
    };
    assert_eq!(
        next.question,
        Question::new(capture.name.clone(), capture.rtype)
    );
}
