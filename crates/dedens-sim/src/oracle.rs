//! What a client may get for a question (D133): the data of an upstream server, a stale copy of it (EDE 3), or a
//! defined failure, never anything else.
//!
//! The data is the whole message an upstream server holds for the question. A response must have the same
//! response code and the same answer records, and no authority or additional record the server did not send; its
//! TTLs may be lower, as a cache counts them down, and no higher than the cache's floor (`min_ttl`) lifts them to,
//! or its stale answer TTL when the answer is stale. A negative answer keeps the SOA the server sent. SERVFAIL
//! without an answer is the defined failure, unless the scenario says the path is live; it and the response codes
//! a scenario accepts carry no answer, no AD, and no authority or additional record the server did not send.
//! DNSSEC records the stub did not ask for (no DO) are not expected.

use dedens_cache::Config;
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Flags, Message, Question, Rcode, Record, RecordType};

/// The message an upstream server holds for a question.
#[derive(Debug, Clone)]
pub struct Expected {
    pub(crate) question: Question<'static>,
    rcode: Rcode,
    answer: Vec<Record<'static>>,
    authority: Vec<Record<'static>>,
    additional: Vec<Record<'static>>,
}

impl Expected {
    /// What `message` holds: the first question, as the question it answers.
    ///
    /// # Panics
    ///
    /// When `message` has no question.
    #[must_use]
    pub fn of(message: &Message<'static>) -> Self {
        Self {
            question: message
                .questions
                .first()
                .expect("a message with a question")
                .clone(),
            rcode: message.rcode(),
            answer: message.answer.clone(),
            authority: message.authority.clone(),
            additional: message.additional.clone(),
        }
    }
}

/// What a scenario accepts besides the data: its defaults are those of a stub asking a plain forwarder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    /// Response codes accepted whatever the data: REFUSED for a client the access list denies, for one.
    pub accept: Vec<Rcode>,
    /// Whether the responses carry AD (RFC 4035 §3.2.3): the expected verdict of a validating pipeline.
    pub authentic: bool,
    /// Whether the stub asks for DNSSEC records (DO): the responses carry the RRSIG, NSEC and NSEC3 records of the
    /// data, and without it they must not be expected.
    pub dnssec: bool,
    /// Whether the path to an upstream server is up, so a query must not end in SERVFAIL.
    pub live: bool,
    /// The TTL a response may carry whatever the data's: the pipeline's cache's `min_ttl`. A scenario that builds
    /// the cache with another sets it too.
    pub floor: u32,
    /// The TTL of a stale answer, whatever the data's: the cache's `stale_answer_ttl` (RFC 8767 §4), set as `floor`
    /// is.
    pub stale_ttl: u32,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            accept: Vec::new(),
            authentic: false,
            dnssec: false,
            live: false,
            floor: Config::default().min_ttl,
            stale_ttl: Config::default().stale_answer_ttl,
        }
    }
}

/// Whether `message` carries EDE 3, Stale Answer (RFC 8914 §4.4): a copy the cache kept past its TTL (RFC 8767).
#[must_use]
pub fn is_stale(message: &Message<'_>) -> bool {
    message
        .edns
        .iter()
        .flat_map(|edns| &edns.options)
        .any(|option| matches!(option, EdnsOption::Ede(ede) if ede.code == InfoCode::STALE_ANSWER))
}

/// Whether two records are the same data: TTLs are the cache's to count down.
fn same(a: &Record<'_>, b: &Record<'_>) -> bool {
    a.name == b.name && a.class == b.class && a.rdata == b.rdata
}

/// Whether `record` is one a server sends only to a query with DO, unless it is what `question` asks for (RFC 4035
/// §3.2.1): the signatures and the proofs of non-existence.
pub(crate) fn withheld(record: &Record<'_>, question: &Question<'_>) -> bool {
    record.rtype() != question.qtype
        && matches!(
            record.rtype(),
            RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
        )
}

/// Whether a stub asking for `question` expects `record` of the data.
fn wanted(record: &Record<'_>, question: &Question<'_>, rules: &Rules) -> bool {
    rules.dnssec || !withheld(record, question)
}

/// Checks the records `got` of the section `section` against those `held`: each is a different one of them with no
/// more TTL than allowed, and every one `wanted` is there when `whole`.
fn section(
    section: &str,
    held: &[Record<'static>],
    got: &[Record<'_>],
    ceiling: &dyn Fn(&Record<'_>) -> u32,
    wanted: &dyn Fn(&Record<'_>) -> bool,
    whole: bool,
) -> Result<(), String> {
    let mut used = vec![false; held.len()];
    for record in got {
        let found = held
            .iter()
            .enumerate()
            .find(|(at, want)| !used[*at] && same(want, record));
        let Some((at, want)) = found else {
            return Err(format!(
                "{section}: not held by the server, or repeated: {record:?}"
            ));
        };
        if record.ttl.get() > ceiling(want) {
            return Err(format!(
                "{section}: TTL above the server's {}: {record:?}",
                want.ttl.get()
            ));
        }
        used[at] = true;
    }
    if whole
        && let Some((lost, _)) = held
            .iter()
            .zip(&used)
            .find(|(want, used)| !**used && wanted(want))
    {
        return Err(format!("{section}: missing: {lost:?}"));
    }
    Ok(())
}

/// Checks `message` against one server's `held`.
fn matches(
    held: &Expected,
    rules: &Rules,
    question: &Question<'_>,
    message: &Message<'_>,
) -> Result<(), String> {
    if message.rcode() != held.rcode {
        return Err(format!(
            "response code {} where the server sent {}",
            message.rcode(),
            held.rcode
        ));
    }
    // A truncated response holds some of the records (RFC 1035 §4.2.1).
    let cut = message.header.flags.contains(Flags::TC);
    // A stale answer has the TTL of the stale answer setting, whatever the record's.
    let lift = if is_stale(message) {
        rules.stale_ttl
    } else {
        0
    };
    let ceiling = |want: &Record<'_>| want.ttl.get().max(rules.floor).max(lift);
    let needed = |record: &Record<'_>| wanted(record, question, rules);
    section(
        "answer",
        &held.answer,
        &message.answer,
        &ceiling,
        &needed,
        !cut,
    )?;
    section(
        "authority",
        &held.authority,
        &message.authority,
        &ceiling,
        &needed,
        false,
    )?;
    section(
        "additional",
        &held.additional,
        &message.additional,
        &ceiling,
        &needed,
        false,
    )?;
    // A negative answer is cached for the SOA's sake: it keeps it.
    let soa = |records: &[Record<'_>]| records.iter().any(|r| r.rtype() == RecordType::SOA);
    if !cut && soa(&held.authority) && !soa(&message.authority) {
        return Err("authority: the SOA of the negative answer is missing".into());
    }
    Ok(())
}

/// Checks a response that carries no data, SERVFAIL or a code the scenario accepts: no answer, no AD, and no
/// authority or additional record the servers did not send for the question.
fn bare(
    expected: &[Expected],
    rules: &Rules,
    question: &Question<'_>,
    message: &Message<'_>,
) -> Result<(), String> {
    if !message.answer.is_empty() {
        return Err(format!(
            "records in the answer of {}: {:?}",
            message.rcode(),
            message.answer
        ));
    }
    if message.header.flags.contains(Flags::AD) {
        return Err(format!(
            "AD on {}, which vouches for no data",
            message.rcode()
        ));
    }
    let held: Vec<Record<'static>> = expected
        .iter()
        .filter(|held| held.question == *question)
        .flat_map(|held| {
            held.answer
                .iter()
                .chain(&held.authority)
                .chain(&held.additional)
        })
        .cloned()
        .collect();
    let ceiling = |want: &Record<'_>| want.ttl.get().max(rules.floor);
    for (name, got) in [
        ("authority", &message.authority),
        ("additional", &message.additional),
    ] {
        section(name, &held, got, &ceiling, &|_| false, false)?;
    }
    Ok(())
}

/// Judges `message`, a response to `question`: `Ok` when a client may get it, why not otherwise.
///
/// # Errors
///
/// The first rule it breaks, for the server that came closest: the last one tried.
pub fn judge(
    expected: &[Expected],
    rules: &Rules,
    question: &Question<'_>,
    message: &Message<'_>,
) -> Result<(), String> {
    if rules.accept.contains(&Rcode::NOERROR) {
        return Err("NOERROR is the data's: no scenario accepts it whatever the data".into());
    }
    let rcode = message.rcode();
    if rcode == Rcode::SERVFAIL && message.answer.is_empty() {
        if rules.live {
            return Err("SERVFAIL where the path is live".into());
        }
        return bare(expected, rules, question, message);
    }
    if rules.accept.contains(&rcode) {
        return bare(expected, rules, question, message);
    }
    if message.header.flags.contains(Flags::AD) != rules.authentic {
        return Err(format!(
            "AD is {} where the scenario expects {}",
            !rules.authentic, rules.authentic
        ));
    }
    let mut why = format!("no server holds data for {question:?}");
    for held in expected.iter().filter(|held| held.question == *question) {
        match matches(held, rules, question, message) {
            Ok(()) => return Ok(()),
            Err(error) => why = error,
        }
    }
    Err(why)
}

#[cfg(test)]
mod tests {
    use dedens_proto::Ttl;
    use dedens_proto::edns::{Edns, ExtendedError};

    use super::*;
    use crate::upstream::captured_message;

    fn held(case: &str) -> (Expected, Message<'static>) {
        let message = captured_message(case);
        (Expected::of(&message), message)
    }

    fn lower(message: &mut Message<'static>, by: u32) {
        for record in message
            .answer
            .iter_mut()
            .chain(&mut message.authority)
            .chain(&mut message.additional)
        {
            record.ttl = Ttl::from_wire(record.ttl.get().saturating_sub(by));
        }
    }

    fn judged(case: &str, change: impl FnOnce(&mut Message<'static>)) -> Result<(), String> {
        judged_by(&Rules::default(), case, change)
    }

    fn judged_by(
        rules: &Rules,
        case: &str,
        change: impl FnOnce(&mut Message<'static>),
    ) -> Result<(), String> {
        let (held, mut message) = held(case);
        change(&mut message);
        judge(&[held], rules, &message.questions[0].clone(), &message)
    }

    #[test]
    fn the_data_is_a_response_with_the_same_or_lower_ttls() {
        for case in ["a", "soa", "nodata", "nxdomain_soa", "txt_large"] {
            assert_eq!(judged(case, |_| {}), Ok(()), "{case}");
            assert_eq!(judged(case, |m| lower(m, 5)), Ok(()), "{case}");
        }
    }

    #[test]
    fn a_higher_ttl_is_refused_unless_the_floor_lifts_it() {
        let floor = Rules::default().floor;
        let ttl = held("a").1.answer[0].ttl.get();
        let raise = |m: &mut Message<'static>| {
            m.answer[0].ttl = Ttl::from_wire(ttl.max(floor) + 1);
        };
        assert!(judged("a", raise).is_err());
        // A TTL under the floor comes out at the floor.
        let rules = Rules {
            floor: ttl.max(floor) + 1,
            ..Rules::default()
        };
        assert_eq!(judged_by(&rules, "a", raise), Ok(()));
    }

    #[test]
    fn other_data_is_refused() {
        assert!(judged("a", |m| drop(m.answer.pop())).is_err(), "missing");
        assert!(
            judged("a", |m| m
                .answer
                .extend(captured_message("txt_large").answer))
            .is_err(),
            "extra"
        );
        assert!(
            judged("a", |m| m.answer = captured_message("txt_large").answer).is_err(),
            "other"
        );
        assert!(
            judged("a", |m| m.answer[0].rdata = m.answer[1].rdata.clone()).is_err(),
            "same data twice"
        );
        let name = captured_message("txt_large").answer[0].name.clone();
        assert!(
            judged("a", |m| m
                .answer
                .iter_mut()
                .for_each(|r| r.name = name.clone()))
            .is_err(),
            "renamed"
        );
        assert!(
            judged("a", |m| m.set_rcode(Rcode::NXDOMAIN).expect("a code")).is_err(),
            "response code"
        );
    }

    #[test]
    fn the_authority_and_additional_sections_hold_nothing_new() {
        let soa = captured_message("nxdomain_soa").authority[0].clone();
        assert!(judged("a", |m| m.authority.push(soa)).is_err(), "authority");
        let extra = captured_message("txt_large").answer[0].clone();
        assert!(
            judged("a", |m| m.additional.push(extra)).is_err(),
            "additional"
        );
    }

    #[test]
    fn a_negative_answer_keeps_its_soa() {
        for case in ["nodata", "nxdomain_soa"] {
            assert!(judged(case, |m| m.authority.clear()).is_err(), "{case}");
        }
    }

    #[test]
    fn a_truncated_response_holds_some_of_the_records() {
        let cut = |m: &mut Message<'static>| {
            m.answer.pop();
            m.header.flags = m.header.flags.with(Flags::TC);
        };
        assert_eq!(judged("a", cut), Ok(()));
        // Not records the server never sent.
        assert!(
            judged("a", |m| {
                cut(m);
                m.answer.extend(captured_message("txt_large").answer);
            })
            .is_err()
        );
    }

    #[test]
    fn ad_is_what_the_scenario_expects() {
        let ad = |m: &mut Message<'static>| m.header.flags = m.header.flags.with(Flags::AD);
        assert!(judged("a", ad).is_err());
        let rules = Rules {
            authentic: true,
            ..Rules::default()
        };
        assert_eq!(judged_by(&rules, "a", ad), Ok(()));
        assert!(judged_by(&rules, "a", |_| {}).is_err());
    }

    #[test]
    fn servfail_is_a_defined_failure_unless_the_path_is_live() {
        let fail = |m: &mut Message<'static>| {
            m.answer.clear();
            m.authority.clear();
            m.set_rcode(Rcode::SERVFAIL).expect("a code");
        };
        assert_eq!(judged("a", fail), Ok(()));
        let live = Rules {
            live: true,
            ..Rules::default()
        };
        assert!(judged_by(&live, "a", fail).is_err());
        // SERVFAIL with an answer is not the defined failure.
        assert!(judged("a", |m| m.set_rcode(Rcode::SERVFAIL).expect("a code")).is_err());
    }

    /// A signed answer to an A query: the A records and their RRSIG.
    fn signed() -> Message<'static> {
        let wire = std::fs::read(dedens_testkit::path("dnssec/alg13_a.bin"))
            .expect("the capture is there");
        let mut message = crate::upstream::decode(&wire);
        // The validation tests' captures set AD only when a validator did.
        message.header.flags = message.header.flags.without(Flags::AD);
        message
    }

    #[test]
    fn signatures_are_for_the_stubs_that_ask_for_them() {
        let signed = signed();
        let question = signed.questions[0].clone();
        let held = [Expected::of(&signed)];
        assert!(
            signed.answer.iter().any(|r| r.rtype() == RecordType::RRSIG),
            "the capture is signed"
        );
        let mut bare = signed.clone();
        bare.answer.retain(|r| r.rtype() != RecordType::RRSIG);
        let dnssec = Rules {
            dnssec: true,
            ..Rules::default()
        };
        let plain = Rules::default();
        // With DO the signatures come, and are missed when they do not.
        assert_eq!(judge(&held, &dnssec, &question, &signed), Ok(()));
        assert!(judge(&held, &dnssec, &question, &bare).is_err());
        // Without it they are not expected.
        assert_eq!(judge(&held, &plain, &question, &bare), Ok(()));
    }

    #[test]
    fn other_response_codes_are_for_the_scenario_to_accept() {
        let refuse = |m: &mut Message<'static>| {
            m.answer.clear();
            m.set_rcode(Rcode::REFUSED).expect("a code");
        };
        assert!(judged("a", refuse).is_err());
        let rules = Rules {
            accept: vec![Rcode::REFUSED],
            ..Rules::default()
        };
        assert_eq!(judged_by(&rules, "a", refuse), Ok(()));
    }

    #[test]
    fn only_signatures_and_proofs_are_withheld_from_a_query_without_do() {
        let signed = signed();
        let question = signed.questions[0].clone();
        let [a, .., rrsig] = signed.answer.as_slice() else {
            panic!("the capture is an answer and its signature");
        };
        assert_eq!(rrsig.rtype(), RecordType::RRSIG);
        assert!(!withheld(a, &question));
        assert!(withheld(rrsig, &question));
        // Another type that is not asked for stays: the SOA of a negative answer.
        let soa = &captured_message("nxdomain_soa").authority[0];
        assert!(!withheld(soa, &question));
        // What is asked for stays.
        let asked = crate::stub::question("cloudflare.com", RecordType::RRSIG);
        assert!(!withheld(rrsig, &asked));
    }

    #[test]
    fn a_failure_carries_no_data_nor_vouching() {
        let fail = |m: &mut Message<'static>| {
            m.answer.clear();
            m.authority.clear();
            m.set_rcode(Rcode::SERVFAIL).expect("a code");
        };
        let foreign = captured_message("nxdomain_soa").authority[0].clone();
        assert!(
            judged("a", |m| {
                fail(m);
                m.authority.push(foreign);
            })
            .is_err(),
            "a record the server never sent"
        );
        assert!(
            judged("a", |m| {
                fail(m);
                m.header.flags = m.header.flags.with(Flags::AD);
            })
            .is_err(),
            "AD on SERVFAIL"
        );
        // What the server did send, in the section it came in, may stay.
        assert_eq!(
            judged("nxdomain_soa", |m| {
                m.answer.clear();
                m.set_rcode(Rcode::SERVFAIL).expect("a code");
            }),
            Ok(())
        );
    }

    #[test]
    fn an_accepted_code_carries_no_data_nor_vouching() {
        let rules = Rules {
            accept: vec![Rcode::REFUSED],
            ..Rules::default()
        };
        let refuse = |m: &mut Message<'static>| m.set_rcode(Rcode::REFUSED).expect("a code");
        assert!(judged_by(&rules, "a", refuse).is_err(), "the answer stays");
        assert!(
            judged_by(&rules, "a", |m| {
                refuse(m);
                m.answer.clear();
                m.header.flags = m.header.flags.with(Flags::AD);
            })
            .is_err(),
            "AD"
        );
    }

    #[test]
    fn no_scenario_accepts_noerror_whatever_the_data() {
        let rules = Rules {
            accept: vec![Rcode::NOERROR],
            ..Rules::default()
        };
        assert!(judged_by(&rules, "a", |_| {}).is_err());
    }

    #[test]
    fn a_record_the_server_sent_once_comes_once() {
        assert!(judged("a", |m| m.answer.push(m.answer[0].clone())).is_err());
    }

    #[test]
    fn a_stale_answer_has_the_stale_ttl() {
        let ttl = held("a").1.answer[0].ttl.get().max(Rules::default().floor);
        let rules = Rules {
            stale_ttl: ttl + 10,
            ..Rules::default()
        };
        let lift = |m: &mut Message<'static>| m.answer[0].ttl = Ttl::from_wire(ttl + 10);
        let stale = |m: &mut Message<'static>| {
            lift(m);
            let mut edns = Edns::default();
            edns.options.push(EdnsOption::Ede(ExtendedError {
                code: InfoCode::STALE_ANSWER,
                text: String::new().into(),
            }));
            m.edns = Some(edns);
        };
        assert_eq!(judged_by(&rules, "a", stale), Ok(()));
        // Not stale: the data's TTL is the bound.
        assert!(judged_by(&rules, "a", lift).is_err());
        // Stale, but over the stale TTL.
        assert!(judged_by(&Rules::default(), "a", stale).is_err());
    }

    #[test]
    fn a_question_no_server_holds_is_refused() {
        let (_, message) = held("a");
        let other = captured_message("txt_large").questions[0].clone();
        let (txt, _) = held("txt_large");
        assert!(judge(&[txt], &Rules::default(), &message.questions[0], &message).is_err());
        assert!(judge(&[], &Rules::default(), &other, &message).is_err());
    }

    #[test]
    fn any_server_may_be_the_one() {
        let (a, message) = held("a");
        let (txt, _) = held("txt_large");
        let question = message.questions[0].clone();
        assert_eq!(
            judge(&[txt, a], &Rules::default(), &question, &message),
            Ok(())
        );
    }

    #[test]
    fn stale_is_ede_3() {
        let mut message = captured_message("a");
        assert!(!is_stale(&message));
        let mut edns = Edns::default();
        edns.options.push(EdnsOption::Ede(ExtendedError {
            code: InfoCode::STALE_ANSWER,
            text: String::new().into(),
        }));
        message.edns = Some(edns);
        assert!(is_stale(&message));
    }
}
