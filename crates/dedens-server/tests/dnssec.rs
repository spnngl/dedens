//! Validation in the server core: AD, the cache of verdicts, and the limits on the validator's work.

mod validation {
    //! RFC 4035 in the validating forward stage (D77): what a validating resolver answers (§3.2), caches (§4.5, §4.7)
    //! and sends (§4.6, §4.8). Upstream answers from the captures of `testdata/dnssec` (its `README.md`), the
    //! validation at the time of their run.

    use dedens_proto::edns::{EdnsOption, InfoCode};
    use dedens_proto::{Flags, Message, Rcode, RecordType};
    use dedens_testkit::dnssec::{Captures, capture};

    use crate::util::{client_query, decode, run_captured, validating, with_flags};

    /// The reply to a query, the requests upstream, and what the pipeline replied.
    fn ask(
        name: &str,
        qtype: RecordType,
        flags: Flags,
        dnssec: bool,
    ) -> (Vec<Message<'static>>, Vec<u8>) {
        let pipeline = validating();
        let done = run_captured(
            &pipeline,
            &client_query(name, qtype, flags, dnssec),
            0,
            &Captures::new(),
        );
        (done.requests, done.reply.expect("a reply"))
    }

    /// Whether `items` has one: `is_empty` and `first` are both linted in an assertion.
    fn some<T>(items: &[T]) -> bool {
        matches!(items, [_, ..])
    }

    fn signed(reply: &Message<'_>) -> bool {
        reply
            .answer
            .iter()
            .chain(&reply.authority)
            .any(|record| record.rtype() == RecordType::RRSIG)
    }

    fn error(reply: &Message<'_>) -> Option<InfoCode> {
        reply
            .edns
            .as_ref()?
            .options
            .iter()
            .find_map(|option| match option {
                EdnsOption::Ede(ede) => Some(ede.code),
                _ => None,
            })
    }

    /// §3.2.3: the answer of a secure zone checked up to the trust anchor is authentic, and says so. §3.2.1: the
    /// signatures come with it for a client that set DO.
    #[test]
    fn a_secure_answer_has_ad_and_its_signatures_for_clients_with_do() {
        let (requests, wire) = ask("cloudflare.com.", RecordType::A, Flags::NONE, true);
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AD));
        assert!(signed(&reply));
        assert!(requests.len() > 1, "the chain of trust is asked for");
    }

    /// §3.2.1: a client that did not set DO gets no DNSSEC record, §3.2.3 and RFC 6840 §5.8: AD when it asked with AD.
    #[test]
    fn signatures_are_left_out_for_clients_without_do() {
        let (_, wire) = ask("cloudflare.com.", RecordType::A, Flags::AD, false);
        let reply = decode(&wire);
        assert!(reply.header.flags.contains(Flags::AD));
        assert!(!signed(&reply));
        assert!(some(&reply.answer));
    }

    /// §3.2.3: an answer of an unsigned zone is insecure: no AD.
    #[test]
    fn an_insecure_answer_has_no_ad() {
        let (_, wire) = ask("google.com.", RecordType::A, Flags::AD, true);
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(!reply.header.flags.contains(Flags::AD));
        assert!(some(&reply.answer));
    }

    /// §5.5, RFC 8914 §4.7: an answer that fails validation is SERVFAIL, with the reason.
    #[test]
    fn a_bogus_answer_is_servfail_with_an_extended_error() {
        for (name, code) in [
            ("dnssec-failed.org.", InfoCode::DNSKEY_MISSING),
            ("sigfail.verteiltesysteme.net.", InfoCode::DNSSEC_BOGUS),
        ] {
            let (_, wire) = ask(name, RecordType::A, Flags::NONE, true);
            let reply = decode(&wire);
            assert_eq!(reply.rcode(), Rcode::SERVFAIL, "{name}");
            assert!(reply.answer.is_empty(), "{name}");
            assert!(!reply.header.flags.contains(Flags::AD));
            assert_eq!(error(&reply), Some(code), "{name}");
        }
    }

    /// §3.2.2: a client that set CD gets the data whatever its signatures, as it came, AD clear, and no validation
    /// was asked for.
    #[test]
    fn a_client_with_cd_gets_bogus_data_unvalidated() {
        let (requests, wire) = ask("dnssec-failed.org.", RecordType::A, Flags::CD, true);
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(some(&reply.answer));
        assert!(!reply.header.flags.contains(Flags::AD));
        assert!(reply.header.flags.contains(Flags::CD));
        assert_eq!(requests.len(), 1);
    }

    /// §4.7: bad data is kept for a short time that the resolver sets, 60 seconds; a client that did not disable
    /// checking gets SERVFAIL from it, one that did gets the data (§3.2.2); then it is validated again.
    #[test]
    fn bogus_data_is_cached_for_sixty_seconds() {
        let pipeline = validating();
        let captures = Captures::new();
        let query = client_query("dnssec-failed.org.", RecordType::A, Flags::NONE, true);
        let first = run_captured(&pipeline, &query, 100, &captures);
        assert!(some(&first.requests));
        let cached = run_captured(&pipeline, &query, 159, &captures);
        assert_eq!(cached.requests.len(), 0, "answered from the cache");
        let wire = cached.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
        assert_eq!(error(&reply), Some(InfoCode::DNSKEY_MISSING));

        let disabled = client_query("dnssec-failed.org.", RecordType::A, Flags::CD, true);
        let served = run_captured(&pipeline, &disabled, 159, &captures);
        assert_eq!(served.requests.len(), 0, "the data comes from the cache");
        let wire = served.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(some(&reply.answer));

        let again = run_captured(&pipeline, &query, 161, &captures);
        assert!(some(&again.requests), "validated again");
    }

    /// §4.5: a validated response is one entry with its signatures: a client's next query is answered from it, AD
    /// following the client's query and the verdict.
    #[test]
    fn a_validated_answer_is_cached_whole() {
        let pipeline = validating();
        let captures = Captures::new();
        let asked = |flags, dnssec| {
            let query = client_query("cloudflare.com.", RecordType::A, flags, dnssec);
            let done = run_captured(&pipeline, &query, 1, &captures);
            (
                done.requests.len(),
                decode(&done.reply.expect("a reply")).into_owned(),
            )
        };
        let (first, _) = asked(Flags::NONE, true);
        assert!(first > 1);
        let (hit, reply) = asked(Flags::NONE, true);
        assert_eq!(hit, 0);
        assert!(reply.header.flags.contains(Flags::AD));
        assert!(signed(&reply));
        let (hit, reply) = asked(Flags::NONE, false);
        assert_eq!(
            hit, 1,
            "another key: the answer for a client without DO, its chain from the key cache (D86)"
        );
        assert!(!reply.header.flags.contains(Flags::AD));
        let (hit, reply) = asked(Flags::AD, false);
        assert_eq!(hit, 0);
        assert!(reply.header.flags.contains(Flags::AD));
        assert!(!signed(&reply));
    }

    /// §4.6: queries clear AD; RFC 6840 §5.9: and set CD, with DO, and none of the client's options, for the client's
    /// question and for each of the validator's.
    #[test]
    fn every_query_upstream_has_do_and_cd_and_no_ad() {
        let pipeline = validating();
        let query = client_query("cloudflare.com.", RecordType::A, Flags::AD, false);
        let done = run_captured(&pipeline, &query, 0, &Captures::new());
        assert!(done.requests.len() > 1);
        for request in &done.requests {
            assert_eq!(request.header.flags, Flags::RD | Flags::CD);
            let edns = request.edns.as_ref().expect("EDNS");
            assert!(edns.flags.contains(dedens_proto::edns::EdnsFlags::DO));
            assert_eq!(edns.options, []);
        }
    }

    /// §4.8: the CNAME a DNAME makes is covered by the DNAME's signature, and the answer keeps it.
    #[test]
    fn the_cname_a_dname_makes_stays_in_the_secure_answer() {
        let (_, wire) = ask(
            "www.dname.sidnlabs.nl.",
            RecordType::AAAA,
            Flags::NONE,
            true,
        );
        let reply = decode(&wire);
        assert!(reply.header.flags.contains(Flags::AD));
        let types: Vec<RecordType> = reply
            .answer
            .iter()
            .map(dedens_proto::Record::rtype)
            .collect();
        assert!(types.contains(&RecordType::DNAME), "{types:?}");
        assert!(types.contains(&RecordType::CNAME), "{types:?}");
        assert!(types.contains(&RecordType::AAAA), "{types:?}");
    }

    /// §3.2.3 and RFC 6840 §5.8: AD says all of the answer is authentic: a chain that goes on in an unsigned zone
    /// is delivered without it, whatever the CNAMEs signed.
    #[test]
    fn an_answer_that_leaves_the_secure_zone_has_no_ad() {
        let (_, wire) = ask("www.ripe.net.", RecordType::A, Flags::AD, true);
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(some(&reply.answer));
        assert!(!reply.header.flags.contains(Flags::AD));
    }

    /// §4.6: the AD bit of an upstream response means nothing without a secure channel: only the verdict sets it.
    #[test]
    fn the_ad_bit_of_upstream_is_ignored() {
        let pipeline = validating();
        let lying = with_flags(capture("google_com_a"), Flags::AD);
        let captures = Captures::new().with(lying);
        let query = client_query("google.com.", RecordType::A, Flags::AD, true);
        let done = run_captured(&pipeline, &query, 0, &captures);
        let wire = done.reply.expect("a reply");
        assert!(!decode(&wire).header.flags.contains(Flags::AD));
    }

    /// §3.2.3: the verdict covers the answer and authority sections, not the additional one: what upstream put there
    /// is not handed out.
    #[test]
    fn a_secure_answer_loses_its_additional_section() {
        let mut message = decode(&capture("alg13_a")).into_owned();
        let mut extra = message.answer[0].clone();
        extra.name = dedens_testkit::dns("unsigned.example.");
        message.additional.push(extra);
        let captures = Captures::new().with(crate::util::wire(&message));
        let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
        let done = run_captured(&validating(), &query, 0, &captures);
        let wire = done.reply.expect("a reply");
        let reply = decode(&wire);
        assert!(reply.header.flags.contains(Flags::AD));
        assert!(some(&reply.answer));
        assert_eq!(reply.additional, []);
    }

    /// A record of class IN owned by `owner` with `data`.
    fn record(
        owner: &str,
        ttl: u32,
        data: &dedens_proto::rdata::RData<'_>,
    ) -> dedens_proto::Record<'static> {
        dedens_proto::Record {
            name: dedens_testkit::dns(owner),
            class: dedens_proto::Class::IN,
            ttl: dedens_proto::Ttl::from_wire(ttl),
            rdata: dedens_proto::WireRdata::new(data),
        }
    }

    /// D77, D75: the validator ignores what is not on the name path of the answer; a record the verdict says nothing
    /// of is neither served under AD nor cached as secure: unrelated sets, signatures that sign nothing, authority
    /// sets that are not at or above the answer, other classes.
    #[test]
    fn a_secure_answer_is_cut_to_what_was_verified() {
        let mut message = decode(&capture("alg13_a")).into_owned();
        let a = message.answer[0].clone();
        let foreign = |owner: &str| dedens_proto::Record {
            name: dedens_testkit::dns(owner),
            ..a.clone()
        };
        let signature = message
            .answer
            .iter()
            .find(|record| record.rtype() == RecordType::RRSIG)
            .expect("a signature")
            .clone();
        let ns = record(
            "unrelated.example.",
            300,
            &dedens_proto::rdata::RData::Cname(dedens_testkit::dns("evil.example.")),
        );
        let genuine = message.answer.len();
        message.answer.push(foreign("other.example."));
        message.answer.push(dedens_proto::Record {
            name: dedens_testkit::dns("other.example."),
            ..signature.clone()
        });
        message.answer.push(dedens_proto::Record {
            name: dedens_testkit::dns("orphan.cloudflare.com."),
            ..signature
        });
        message.answer.push(dedens_proto::Record {
            class: dedens_proto::Class::CH,
            ..a.clone()
        });
        message.authority.push(ns);
        message.authority.push(foreign("cloudflare.net."));
        let captures = Captures::new().with(crate::util::wire(&message));
        let pipeline = validating();
        for round in 0..2 {
            let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
            let done = run_captured(&pipeline, &query, round, &captures);
            assert_eq!(done.requests.is_empty(), round == 1, "the second is a hit");
            let wire = done.reply.expect("a reply");
            let reply = decode(&wire);
            assert!(reply.header.flags.contains(Flags::AD));
            assert_eq!(reply.answer.len(), genuine, "{:?}", reply.answer);
            assert_eq!(reply.authority, [], "round {round}");
            assert!(
                reply
                    .answer
                    .iter()
                    .all(|record| record.name == dedens_testkit::dns("cloudflare.com."))
            );
        }
    }

    /// RFC 6672 §3.1, D75: only the CNAME a DNAME makes goes unverified, so a set of it with another record is
    /// checked as any CNAME, unsigned in a secure zone: bogus, never served under AD.
    #[test]
    fn a_second_record_in_the_cname_a_dname_makes_is_bogus() {
        let mut message = decode(&capture("dname_answer")).into_owned();
        let at = message
            .answer
            .iter()
            .position(|record| record.rtype() == RecordType::CNAME)
            .expect("the synthesized CNAME");
        let evil = dedens_proto::Record {
            rdata: dedens_proto::WireRdata::new(&dedens_proto::rdata::RData::Cname(
                dedens_testkit::dns("evil.example."),
            )),
            ..message.answer[at].clone()
        };
        message.answer.insert(at + 1, evil);
        let captures = Captures::new().with(crate::util::wire(&message));
        let query = client_query(
            "www.dname.sidnlabs.nl.",
            RecordType::AAAA,
            Flags::NONE,
            true,
        );
        let done = run_captured(&validating(), &query, 0, &captures);
        let wire = done.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
        assert!(!reply.header.flags.contains(Flags::AD));
        assert_eq!(reply.answer, []);
        assert_eq!(error(&reply), Some(InfoCode::RRSIGS_MISSING));
    }

    /// §4.3: no verdict, for lack of an answer to a question of the validator's: SERVFAIL, held for the next query.
    #[test]
    fn no_verdict_is_servfail_and_held() {
        let pipeline = validating();
        let captures = Captures::new().without("com.", RecordType::DS);
        let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
        let first = run_captured(&pipeline, &query, 0, &captures);
        assert!(
            first.asked.len() > 2,
            "every server was tried: {:?}",
            first.asked
        );
        let wire = first.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
        assert!(!reply.header.flags.contains(Flags::AD));
        assert!(error(&reply).is_some());
        let held = run_captured(&pipeline, &query, 1, &captures);
        assert_eq!(held.requests.len(), 0, "the failure is held");
    }

    /// `genuine` as the response to the question for `name`, its records replaced by `answer`.
    fn response_for(
        genuine: &Message<'static>,
        name: &str,
        answer: Vec<dedens_proto::Record<'static>>,
    ) -> Vec<u8> {
        let mut message = genuine.clone();
        message.questions[0].name = dedens_testkit::dns(name);
        message.answer = answer;
        message.authority.clear();
        message.additional.clear();
        crate::util::wire(&message)
    }

    /// The signed CNAME of `www.ripe.net.` alone, and the rest of its chain: what two responses of upstream are, to
    /// the question for the name and to the one for the CNAME's target.
    fn split_chain() -> (Vec<u8>, Vec<u8>) {
        let genuine = decode(&capture("cname_to_insecure")).into_owned();
        let (head, tail): (Vec<_>, Vec<_>) = genuine
            .answer
            .iter()
            .cloned()
            .partition(|record| record.name == dedens_testkit::dns("www.ripe.net."));
        (
            response_for(&genuine, "www.ripe.net.", head),
            response_for(&genuine, "www.ripe.net.edgekey.net.", tail),
        )
    }

    /// RFC 6840 §5.8, D77: a CNAME chain that stops short is chased, the name it goes on at asked and its response
    /// validated as one of its own; the answer is never secure, whatever the verdicts.
    #[test]
    fn a_chain_that_stops_short_is_chased_and_not_secure() {
        let (head, tail) = split_chain();
        let captures = Captures::new().with(head).with(tail);
        let query = client_query("www.ripe.net.", RecordType::A, Flags::AD, true);
        let done = run_captured(&validating(), &query, 0, &captures);
        let chased = done.requests.iter().any(|request| {
            request.questions[0].name == dedens_testkit::dns("www.ripe.net.edgekey.net.")
        });
        assert!(chased);
        let reply = decode(&done.reply.expect("a reply")).into_owned();
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(!reply.header.flags.contains(Flags::AD));
        assert!(some(&reply.answer));
    }

    /// D77: a chased name upstream does not answer leaves no verdict: SERVFAIL, not the first response as if it were
    /// the whole answer.
    #[test]
    fn a_chased_name_without_an_answer_is_indeterminate() {
        let (head, _) = split_chain();
        let captures = Captures::new()
            .with(head)
            .without("www.ripe.net.edgekey.net.", RecordType::A);
        let query = client_query("www.ripe.net.", RecordType::A, Flags::AD, true);
        let done = run_captured(&validating(), &query, 0, &captures);
        let reply = decode(&done.reply.expect("a reply")).into_owned();
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
        assert!(!reply.header.flags.contains(Flags::AD));
        assert!(!some(&reply.answer));
    }

    /// D77: a server that did not answer is not asked again for the next question of the same query: one dead server
    /// costs the patience of one question, not of each.
    #[test]
    fn a_dead_server_is_asked_once_by_a_query() {
        let dead = crate::util::servers()[0];
        let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
        let done = crate::util::run_captured_without(
            &validating(),
            &query,
            0,
            &Captures::new(),
            Some(dead),
        );
        let reply = decode(&done.reply.expect("a reply")).into_owned();
        assert!(reply.header.flags.contains(Flags::AD));
        assert!(done.requests.len() > 2);
        assert_eq!(
            done.asked.iter().filter(|&&server| server == dead).count(),
            1
        );
    }

    /// §4.7, D77: a refresh whose answer fails validation leaves the entry it refreshes: bad data does not replace data
    /// that is still good.
    #[test]
    fn a_refresh_that_turns_bogus_keeps_the_entry() {
        let pipeline = validating();
        let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
        let first = run_captured(&pipeline, &query, 0, &Captures::new());
        let ttl = decode(&first.reply.expect("a reply")).answer[0].ttl.get();
        assert!(ttl >= 20, "{ttl}");

        let mut forged = decode(&capture("alg13_a")).into_owned();
        for record in &mut forged.answer {
            if record.rtype() == RecordType::A {
                record.rdata = dedens_proto::WireRdata::new(&dedens_proto::rdata::RData::A(
                    std::net::Ipv4Addr::new(192, 0, 2, 66),
                ));
            }
        }
        let captures = Captures::new().with(crate::util::wire(&forged));
        let late = ttl - 1;
        let refresh = run_captured(&pipeline, &query, late, &captures);
        assert!(some(&refresh.requests), "the entry was refreshed");

        let served = run_captured(&pipeline, &query, late, &captures);
        assert_eq!(served.requests.len(), 0, "answered from the cache");
        let reply = decode(&served.reply.expect("a reply")).into_owned();
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AD));
        assert!(reply.answer.iter().all(|record| {
            !matches!(record.data(), dedens_proto::rdata::RData::A(address) if address == std::net::Ipv4Addr::new(192, 0, 2, 66))
        }));
    }
}

mod clarifications {
    //! RFC 6840 in the server core: AD asked upstream as the client asked (§5.7) and kept only for clients that
    //! asked for it (§5.8); CD copied upstream and back (RFC 4035 §3.2.2).

    use dedens_proto::edns::{Edns, EdnsFlags};
    use dedens_proto::{Flags, RecordType, Transport};
    use dedens_testkit::captured;
    use dedens_testkit::dnssec::Captures;

    use crate::util::{
        caching, client_query, decode, forwarder, query_for, run, run_captured, validating, wire,
        with_flags,
    };

    /// No validator (D114): the AD bit of an upstream response is never passed on, whatever the client asked, and
    /// whatever the transport to upstream (RFC 6840 §5.8: AD only for data our validator checked; RFC 4035 §3.2.3).
    /// Forwarded, stored and served from the cache, the reply has AD clear.
    #[test]
    fn ad_of_an_unvalidated_upstream_response_is_cleared() {
        let response = with_flags(captured("a"), Flags::AD);
        assert!(decode(&response).header.flags.contains(Flags::AD));
        for (ad, dnssec) in [
            (Flags::NONE, false),
            (Flags::AD, false),
            (Flags::NONE, true),
            (Flags::AD, true),
        ] {
            let mut query = query_for(&response);
            query.header.flags = Flags::RD | ad;
            query.edns = Some(Edns {
                flags: if dnssec {
                    EdnsFlags::DO
                } else {
                    EdnsFlags::default()
                },
                ..Edns::default()
            });
            let query = wire(&query);
            let done = run(&forwarder(), &query, Transport::Udp, &[Some(&response)]);
            assert_eq!(done.requests[0].header.flags, Flags::RD | ad);
            let reply = done.reply.expect("a reply");
            assert!(
                !decode(&reply).header.flags.contains(Flags::AD),
                "forwarded, AD {ad:?}, DO {dnssec}"
            );

            // The first query stores the response, the second is a hit.
            let pipeline = caching();
            for round in ["miss", "hit"] {
                let done = run(&pipeline, &query, Transport::Udp, &[Some(&response)]);
                let reply = done.reply.expect("a reply");
                assert!(
                    !decode(&reply).header.flags.contains(Flags::AD),
                    "{round}, AD {ad:?}, DO {dnssec}"
                );
            }
        }
    }

    #[test]
    fn cd_goes_upstream_and_back() {
        let response = captured("a");
        for cd in [Flags::CD, Flags::NONE] {
            let mut query = query_for(&response);
            query.header.flags = Flags::RD | cd;
            let done = run(
                &forwarder(),
                &wire(&query),
                Transport::Udp,
                &[Some(&response)],
            );
            assert_eq!(done.requests[0].header.flags, Flags::RD | cd);
            let wire = done.reply.expect("a reply");
            assert_eq!(
                decode(&wire).header.flags.contains(Flags::CD),
                cd == Flags::CD
            );
        }
    }

    /// §5.7-5.8 with validation (D77): a secure answer has AD for a client that set AD or DO, not for one that set
    /// neither; the verdict is the same cached or not.
    #[test]
    fn a_validated_answer_has_ad_only_for_clients_with_ad_or_do() {
        let pipeline = validating();
        let captures = Captures::new();
        for (flags, dnssec, ad) in [
            (Flags::NONE, false, false),
            (Flags::AD, false, true),
            (Flags::NONE, true, true),
            (Flags::NONE, false, false),
        ] {
            let query = client_query("cloudflare.com.", RecordType::A, flags, dnssec);
            let done = run_captured(&pipeline, &query, 0, &captures);
            let wire = done.reply.expect("a reply");
            assert_eq!(
                decode(&wire).header.flags.contains(Flags::AD),
                ad,
                "{flags:?}, DO {dnssec}"
            );
        }
    }

    /// §5.9: CD is set on every upstream query, whether the client set it or not, and the validator's questions too.
    /// §5.6: the DO bit of the reply is the query's.
    #[test]
    fn cd_is_set_on_every_upstream_query_and_do_is_copied_back() {
        let pipeline = validating();
        for dnssec in [true, false] {
            let query = client_query("google.com.", RecordType::A, Flags::NONE, dnssec);
            let done = run_captured(&pipeline, &query, 0, &Captures::new());
            assert!(
                done.requests
                    .iter()
                    .all(|r| r.header.flags.contains(Flags::CD))
            );
            let wire = done.reply.expect("a reply");
            let edns = decode(&wire).edns.expect("our OPT record");
            assert_eq!(edns.flags.contains(EdnsFlags::DO), dnssec);
        }
    }
}

mod limits {
    //! What a client's queries may cost a validating forward stage (D77): the work of one query, an allowance all the
    //! queries share, and the share of it each client network has, past which an uncached query is answered SERVFAIL
    //! without being validated. Upstream answers from the captures of `dedens-dnssec`, the validation at the time of
    //! their run; the buckets count in the `now` of the queries.

    use std::net::IpAddr;
    use std::sync::Arc;

    use dedens_dnssec::{Limits, TrustAnchors, Validator};
    use dedens_proto::edns::{EdnsOption, InfoCode};
    use dedens_proto::{Flags, Rcode, RecordType, Transport};
    use dedens_server::{
        Allowance, Budget, Budgets, Clock, Cookies, Pipeline, RateLimit, RateLimitConfig, Secret,
        Secrets, Validating,
    };
    use dedens_testkit::dnssec::Captures;

    use crate::util::{
        captured_at, client_query, decode, run_captured, run_captured_from, run_together,
        validating_under, wire,
    };

    /// The second the queries start at, far from 0 so that a clock gone back can be tried.
    const START: u32 = 1_000_000;

    /// Validation with no key cache, so that each query walks the chain from the root: each costs the same.
    fn validating(allowance: Allowance) -> Validating {
        let limits = Limits {
            key_cache: 0,
            ..Limits::default()
        };
        Validating::new(
            Validator::new(TrustAnchors::root(), limits),
            Arc::new(captured_at),
        )
        .allowing(allowance)
    }

    /// What a query came to: the questions upstream, and the reply.
    fn ask(pipeline: &Pipeline, name: &str, now: u32) -> (usize, dedens_proto::Message<'static>) {
        let done = run_captured(
            pipeline,
            &client_query(name, RecordType::A, Flags::NONE, true),
            now,
            &Captures::new(),
        );
        (
            done.requests.len(),
            decode(&done.reply.expect("a reply")).into_owned(),
        )
    }

    fn error(reply: &dedens_proto::Message<'_>) -> Option<InfoCode> {
        reply
            .edns
            .as_ref()?
            .options
            .iter()
            .find_map(|option| match option {
                EdnsOption::Ede(ede) => Some(ede.code),
                _ => None,
            })
    }

    /// An allowance of `burst` units that refills fast: a second makes it whole.
    fn allowance(burst: u32) -> Allowance {
        Allowance {
            per_second: 1_000_000,
            burst,
            ..Allowance::default()
        }
    }

    /// D77, D106: the allowance is spent by the questions and the work of the queries validated; one that finds it spent
    /// is answered SERVFAIL, with no question upstream, and nothing of it is held or cached. One that runs it into debt
    /// asks no more questions: it is answered the same, after the step that did.
    #[test]
    fn a_query_past_the_allowance_is_shed_without_being_validated() {
        // One unit left admits a query; its first question takes it, and the debt stops the query there.
        let pipeline = validating_under(validating(allowance(1)));
        let (questions, reply) = ask(&pipeline, "cloudflare.com.", START);
        assert_eq!(questions, 1, "the client's question only");
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
        assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
        // The next finds the allowance in debt.
        let (questions, reply) = ask(&pipeline, "nlnetlabs.nl.", START);
        assert_eq!(questions, 0, "nothing is asked upstream");
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
        assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
        // Shed, not failed: no failure is held, so once the debt is paid the same query is asked upstream again.
        let (questions, reply) = ask(&pipeline, "cloudflare.com.", START + 1);
        assert_eq!(questions, 1, "{questions}");
        assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    }

    /// D77: the allowance refills at its rate, up to its burst, by the `now` of the queries, and never goes back with
    /// it.
    #[test]
    fn the_allowance_refills_at_its_rate_up_to_its_burst() {
        let validating = validating(Allowance {
            per_second: 1,
            burst: 1,
            ..Allowance::default()
        });
        // One query goes into debt of one unit, the most the burst keeps: one second repays it, and leaves none.
        drop(ask(
            &validating_under(validating.clone()),
            "cloudflare.com.",
            START,
        ));
        let (questions, reply) = ask(
            &validating_under(validating.clone()),
            "nlnetlabs.nl.",
            START + 1,
        );
        assert_eq!(questions, 0);
        assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
        // A clock gone back repays nothing.
        let (questions, _) = ask(&validating_under(validating.clone()), "nlnetlabs.nl.", 0);
        assert_eq!(questions, 0);
        // A long while later the burst is all that is back, and admits one query.
        let (questions, _) = ask(
            &validating_under(validating),
            "nlnetlabs.nl.",
            START + 10_000,
        );
        assert_eq!(questions, 1, "{questions}");
    }

    /// A validator that has the keys of `www.icann.org.` and of the name its CNAME goes on at already, so that a query
    /// for it takes no question upstream but the client's and the chasing of the chain: the step that validates the
    /// first response costs a verification and the question that chases, two units or a few more.
    fn keyed() -> Validating {
        let keyed = Validating::new(
            Validator::new(TrustAnchors::root(), Limits::default()),
            Arc::new(captured_at),
        );
        let (questions, reply) = ask(&validating_under(keyed.clone()), "www.icann.org.", START);
        assert!(questions > 2, "{questions}");
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        keyed
    }

    /// D106: the debt stops at one burst: validation is back `burst / per_second + 1` seconds after queries that cost
    /// several times the burst, and not a second before the burst is repaid. Ten queries in flight take the 10 units
    /// of the burst, then cost at least 2 each as they are answered; without the floor the debt of 20 takes 21 s to
    /// repay.
    #[test]
    fn the_debt_of_queries_in_flight_is_at_most_a_burst() {
        let allowing = Allowance {
            per_second: 1,
            burst: 10,
            ..Allowance::default()
        };
        let validating = keyed().allowing(allowing);
        let pipeline = validating_under(validating.clone());
        let (_, replies) = run_together(&pipeline, "www.icann.org.", 10, START, &Captures::new());
        assert_eq!(
            replies.len(),
            10,
            "all were admitted before any was charged"
        );
        let (questions, reply) = ask(
            &validating_under(validating.clone()),
            "nlnetlabs.nl.",
            START + 10,
        );
        assert_eq!(questions, 0, "the debt is not yet repaid");
        assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
        let (questions, _) = ask(&validating_under(validating), "nlnetlabs.nl.", START + 11);
        assert_eq!(questions, 1, "admitted again");
    }

    /// D106: a flood of queries in flight, all admitted before any is charged, asks no more than its units allow: a query
    /// that finds the allowance in debt stops after the step it is in, so that the work past the burst is one step of
    /// each, not the whole chain. 40 queries take 40 of the 60 units at admission; each next question is asked only
    /// after a step that cost a unit and left none owed, so at most 20 are asked. Run to the end, they ask ten times that.
    #[test]
    fn a_flood_in_flight_asks_no_more_than_the_burst_allows() {
        let allowing = Allowance {
            per_second: 1,
            burst: 60,
            ..Allowance::default()
        };
        let pipeline = validating_under(validating(allowing));
        let (requests, replies) =
            run_together(&pipeline, "cloudflare.com.", 40, START, &Captures::new());
        assert!(requests <= 40 + 20, "{requests}");
        assert_eq!(replies.len(), 40);
        for reply in replies.iter().flatten() {
            let reply = decode(reply);
            assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
        }
    }

    /// D77: one query costs at most `per_query` units, the questions it asks upstream and the signatures it checks,
    /// the chasing of a CNAME chain included: past it, no verdict (indeterminate: it was validated in part, so the
    /// failure is held as any other, RFC 9520).
    #[test]
    fn a_query_that_costs_more_than_its_limit_has_no_verdict() {
        let few = Allowance {
            per_query: 3,
            ..allowance(1_000_000)
        };
        let pipeline = validating_under(validating(few));
        let (questions, reply) = ask(&pipeline, "cloudflare.com.", START);
        assert!(questions <= 4, "{questions}");
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
        assert_eq!(error(&reply), Some(InfoCode::DNSSEC_INDETERMINATE));
        // Held: the same query asks nothing upstream now.
        let (questions, reply) = ask(&pipeline, "cloudflare.com.", START);
        assert_eq!(questions, 0, "the failure is held");
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    }

    /// D77: `per_query` is the most a query may spend, not a bound it must stay under: a cold validation of
    /// `cloudflare.com.` has spent 8 units when it asks its last question, and a limit of 8 lets it ask; at 2, the
    /// query that has spent 3 by its second question asks no more.
    #[test]
    fn a_query_may_spend_its_limit_and_no_more() {
        let limited = |per_query| {
            validating_under(validating(Allowance {
                per_query,
                ..allowance(1_000_000)
            }))
        };
        let (_, reply) = ask(&limited(8), "cloudflare.com.", START);
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AD));
        let (questions, reply) = ask(&limited(2), "cloudflare.com.", START);
        assert_eq!(questions, 2, "the client's question and one more");
        assert_eq!(error(&reply), Some(InfoCode::DNSSEC_INDETERMINATE));
    }

    /// The clients of D117's tests, one /24 apart or together.
    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// Cold validations of `name` for the client at `from` over `transport` under `validating`, with `limit` on the
    /// pipeline if any: the questions asked and the reply, a fresh cache each time so that only the buckets differ
    /// between asks.
    fn ask_from(
        validating: &Validating,
        limit: Option<&Arc<RateLimit>>,
        (from, transport): (IpAddr, Transport),
        name: &str,
        now: u32,
    ) -> (usize, dedens_proto::Message<'static>) {
        let pipeline = validating_under(validating.clone());
        let pipeline = match limit {
            Some(limit) => pipeline.with_rate_limit(Arc::clone(limit)),
            None => pipeline,
        };
        let done = run_captured_from(
            &pipeline,
            (from, transport),
            &client_query(name, RecordType::A, Flags::NONE, true),
            now,
            &Captures::new(),
            None,
        );
        (
            done.requests.len(),
            decode(&done.reply.expect("a reply")).into_owned(),
        )
    }

    /// A validation under an allowance of `burst` units, and a share of 20 units that does not refill within a
    /// test, in a million buckets keyed at random: two networks of a test share one once in a million runs, not once in
    /// 256.
    fn sharing(burst: u32) -> Validating {
        validating(Allowance {
            per_second: 1,
            burst,
            ..Allowance::default()
        })
        .sharing(
            Budgets::new(Budget {
                per_second: 1,
                burst: 20,
                table: 1 << 20,
            })
            .expect("a share in bounds"),
        )
    }

    /// Asks cold validations for `from` until one is shed, which the share of 20 units does within 20.
    fn spend_the_share(
        validating: &Validating,
        limit: Option<&Arc<RateLimit>>,
        from: IpAddr,
    ) -> bool {
        (0..20).any(|_| {
            let (_, reply) = ask_from(
                validating,
                limit,
                (from, Transport::Udp),
                "cloudflare.com.",
                START,
            );
            error(&reply) == Some(InfoCode::NOT_READY)
        })
    }

    /// D117: the allowance is global, but each client network spends it only up to its share, so one client cannot
    /// shed the others (the trigger of audit S3: one client with cold validations shed everyone). The greedy client
    /// runs out of its share and is shed with EDE 14, nothing held; its neighbour in the same /24 is shed with it; a
    /// client of another network is still validated, and so is the greedy one once the share is paid down.
    #[test]
    fn a_client_over_its_share_cannot_shed_another_client() {
        let validating = sharing(200);
        let (greedy, neighbour, other) = (
            address("198.51.100.7"),
            address("198.51.100.200"),
            address("203.0.113.9"),
        );
        assert!(
            spend_the_share(&validating, None, greedy),
            "the share is spent within 20 cold validations"
        );
        let (questions, reply) = ask_from(
            &validating,
            None,
            (greedy, Transport::Udp),
            "cloudflare.com.",
            START,
        );
        assert_eq!(questions, 0, "nothing is asked upstream");
        assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
        let (questions, reply) = ask_from(
            &validating,
            None,
            (neighbour, Transport::Udp),
            "nlnetlabs.nl.",
            START,
        );
        assert_eq!(questions, 0, "the /24 shares one budget");
        assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
        let (questions, reply) = ask_from(
            &validating,
            None,
            (other, Transport::Udp),
            "nlnetlabs.nl.",
            START,
        );
        assert!(questions > 0, "another network is validated");
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AD));
        // Shed, not failed: once the share is paid down the greedy client is validated again.
        let (questions, _) = ask_from(
            &validating,
            None,
            (greedy, Transport::Udp),
            "cloudflare.com.",
            START + 100,
        );
        assert!(questions > 0, "admitted again");
    }

    /// D117: a UDP source can be spoofed, so a flood from spoofed addresses of a network spends the share of the
    /// network's unproven queries; a client of the network over TCP, whose address is proven, has a share of its own and
    /// is still validated.
    #[test]
    fn a_proven_client_is_not_shed_by_the_unproven_ones_of_its_network() {
        let validating = sharing(200);
        let victim = address("198.51.100.7");
        assert!(spend_the_share(&validating, None, victim));
        let (questions, reply) = ask_from(
            &validating,
            None,
            (address("198.51.100.8"), Transport::Tcp),
            "nlnetlabs.nl.",
            START,
        );
        assert!(questions > 0, "the connection is validated");
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AD));
    }

    /// D117, RFC 7873 §5.2.5: a valid Server Cookie proves a UDP source as a connection does, so the client has the
    /// proven share of its network, which a flood without cookies does not spend.
    #[test]
    fn a_udp_client_with_a_valid_cookie_is_not_shed_by_the_unproven_ones() {
        let validating = sharing(200);
        assert!(spend_the_share(&validating, None, address("198.51.100.7")));
        let client = address("198.51.100.8");
        let clock: Clock = Arc::new(|| u64::from(START));
        let secret: Secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
            .parse()
            .expect("a secret");
        let cookies = Cookies::new(Secrets::new(secret, vec![]), clock);
        let cookie = cookies.issue([7; 8], client);
        let mut query = decode(&client_query(
            "nlnetlabs.nl.",
            RecordType::A,
            Flags::NONE,
            true,
        ))
        .into_owned();
        let edns = query.edns.as_mut().expect("EDNS");
        edns.options.push(EdnsOption::Cookie(cookie));
        let done = run_captured_from(
            &validating_under(validating).with_cookies(cookies),
            (client, Transport::Udp),
            &wire(&query),
            START,
            &Captures::new(),
            None,
        );
        assert!(!done.requests.is_empty(), "the proven client is validated");
        let reply = decode(&done.reply.expect("a reply")).into_owned();
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AD));
    }

    /// D117: a source on the rate limit's exempt list (D113), which may be a proxy hiding its clients, has no share,
    /// and the global allowance still bounds it.
    #[test]
    fn an_exempt_source_has_no_share() {
        let validating = sharing(10_000);
        let limit = Arc::new(
            RateLimit::new(RateLimitConfig {
                exempt: vec!["198.51.100.0/24".parse().expect("a network")],
                ..RateLimitConfig::default()
            })
            .expect("a limit in bounds"),
        );
        let proxy = address("198.51.100.7");
        assert!(
            !spend_the_share(&validating, Some(&limit), proxy),
            "20 cold validations are over its share, and are not shed"
        );
        // Not exempt: the same asks are shed by the share.
        assert!(spend_the_share(&validating, None, proxy));
    }

    /// D77: a client that disabled checking costs no validation, so the allowance never sheds it.
    #[test]
    fn a_query_that_is_not_validated_is_never_shed() {
        let validating = validating(allowance(0));
        let pipeline = validating_under(validating);
        let query = client_query("cloudflare.com.", RecordType::A, Flags::CD, true);
        let done = run_captured(&pipeline, &query, START, &Captures::new());
        let reply = decode(&done.reply.expect("a reply")).into_owned();
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(!reply.header.flags.contains(Flags::AD));
    }
}
