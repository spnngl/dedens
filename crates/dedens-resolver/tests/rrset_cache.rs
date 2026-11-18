//! The `RRset` cache on captured responses (`testdata/proto`, `testdata/dnssec`): RFC 2181 §5 (`RRsets`), §5.2 (one
//! TTL), §5.4.1 (ranking), §8 (TTL past 2^31 - 1); RFC 1035 §2.3.4 (longest name), §3.2.1 (TTL 0); RFC 4343 (case);
//! RFC 4034 §3 (signatures); RFC 4035 §4.7 (bogus data), §5.3.3 (signed TTL); RFC 6895 §3.1, §3.2 (meta types,
//! QCLASSes); CVE-2026-40622 and CVE-2026-42955 (ghost domain names); D124 (TTL bounds), D116 (byte budget), D193.

use dedens_cache::{Checked, Config, ConfigError, Cost};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::{Opaque, RData, Rrsig, Txt};
use dedens_proto::{Class, Message, Record, RecordType, Section, Ttl};
use dedens_resolver::{DEFAULT_CAPACITY, Hit, Inserted, NotCached, Rank, Rrset, RrsetCache};
use dedens_testkit::{captured, dns, dnssec, message};

const RANKS: [Rank; 6] = [
    Rank::AdditionalNonAuthoritative,
    Rank::AuthorityNonAuthoritative,
    Rank::AdditionalAuthoritative,
    Rank::AnswerNonAuthoritative,
    Rank::AuthorityAuthoritative,
    Rank::AnswerAuthoritative,
];

const BOGUS: Checked = Checked::Bogus(InfoCode::DNSSEC_BOGUS);

fn cache() -> RrsetCache {
    RrsetCache::new(1 << 20, Config::default()).expect("a valid config")
}

fn section<'m>(message: &'m Message<'static>, section: Section) -> &'m [Record<'static>] {
    match section {
        Section::Answer => &message.answer,
        Section::Authority => &message.authority,
        Section::Additional => &message.additional,
    }
}

/// The `RRsets` of `section` of the response captured as `case` in `testdata/proto`.
fn rrsets(case: &str, from: Section) -> Vec<Rrset> {
    Rrset::group(section(&message(&captured(case)), from))
}

/// The one `RRset` of `section` of `case`.
fn rrset(case: &str, from: Section) -> Rrset {
    let [rrset] = <[Rrset; 1]>::try_from(rrsets(case, from)).expect("one RRset");
    rrset
}

/// The records of `section` of `case` but the first: another `RRset` of the same name, type and class.
fn fewer(case: &str, from: Section) -> Rrset {
    let message = message(&captured(case));
    let [rrset] =
        <[Rrset; 1]>::try_from(Rrset::group(&section(&message, from)[1..])).expect("one RRset");
    rrset
}

/// `example.com. A`, two records, TTL 29, from a recursive resolver.
fn a() -> Rrset {
    rrset("a", Section::Answer)
}

fn get(cache: &RrsetCache, rrset: &Rrset, now: u32) -> Option<Hit> {
    cache.get(rrset.owner(), rrset.rtype(), rrset.class(), now)
}

/// The hit of an `RRset` stored.
#[track_caller]
fn stored(inserted: Result<Inserted, NotCached>) -> Hit {
    match inserted {
        Ok(Inserted::Stored(hit)) => hit,
        other => unreachable!("not stored: {other:?}"),
    }
}

/// The hit of the `RRset` kept.
#[track_caller]
fn kept(inserted: Result<Inserted, NotCached>) -> Hit {
    match inserted {
        Ok(Inserted::Kept(hit)) => hit,
        other => unreachable!("not kept: {other:?}"),
    }
}

/// The hit of the `RRset` that took a verdict.
#[track_caller]
fn verdict(inserted: Result<Inserted, NotCached>) -> Hit {
    match inserted {
        Ok(Inserted::Verdict(hit)) => hit,
        other => unreachable!("no verdict: {other:?}"),
    }
}

/// `records`, the name of each in capitals.
fn shouted(records: &[Record<'static>]) -> Vec<Record<'static>> {
    records
        .iter()
        .map(|r| Record {
            name: dns(&r.name.to_string().to_uppercase()),
            ..r.clone()
        })
        .collect()
}

#[test]
fn rfc2181_5_group_keeps_one_rrset_per_name_type_and_class() {
    let glue = rrsets("referral_root", Section::Additional);
    // 13 servers, an A and an AAAA RRset each.
    assert_eq!(glue.len(), 26);
    let ns = rrset("referral_root", Section::Authority);
    assert_eq!((ns.rtype(), ns.rdatas().len()), (RecordType::NS, 13));
    // The same data in another order compares equal.
    let message = message(&captured("referral_root"));
    let mut reversed = message.authority.clone();
    reversed.reverse();
    assert_eq!(Rrset::group(&reversed), [ns]);
}

#[test]
fn rfc2181_5_group_drops_duplicates() {
    let message = message(&captured("a"));
    let twice: Vec<Record<'_>> = message
        .answer
        .iter()
        .chain(&message.answer)
        .cloned()
        .collect();
    assert_eq!(Rrset::group(&twice), [a()]);
}

/// NS records naming the same servers in another case are duplicates (RFC 4343), in whatever order they come.
#[test]
fn rfc4343_group_drops_duplicates_differing_in_case() {
    let ns = rrset("referral_root", Section::Authority);
    let message = message(&captured("referral_root"));
    let capitals: Vec<Record<'static>> = message
        .authority
        .iter()
        .map(|record| {
            let RData::Ns(server) = record.data() else {
                panic!("an NS record: {record:?}");
            };
            let server = dns(&server.to_string().to_uppercase());
            Record::new(
                record.name.clone(),
                record.class,
                record.ttl,
                &RData::Ns(server),
            )
        })
        .collect();
    let mut both: Vec<Record<'static>> =
        capitals.iter().chain(&message.authority).cloned().collect();
    let [set] = <[Rrset; 1]>::try_from(Rrset::group(&both)).expect("one RRset");
    assert_eq!(set.rdatas().len(), 13);
    assert_eq!(set, ns);
    both.reverse();
    assert_eq!(Rrset::group(&both), [ns]);
}

/// Records of another class are another `RRset`, and another key in the cache (RFC 2181 §5).
#[test]
fn rfc2181_5_classes_are_kept_apart() {
    let message = message(&captured("a"));
    let chaos: Vec<Record<'static>> = message.answer[..1]
        .iter()
        .map(|r| Record {
            class: Class::CH,
            ..r.clone()
        })
        .collect();
    let records: Vec<Record<'static>> = message.answer.iter().chain(&chaos).cloned().collect();
    let sets = Rrset::group(&records);
    assert_eq!(
        sets.iter()
            .map(|s| (s.class(), s.rdatas().len()))
            .collect::<Vec<_>>(),
        [(Class::IN, 2), (Class::CH, 1)]
    );
    let cache = cache();
    for set in sets {
        stored(cache.insert(set, Rank::AnswerNonAuthoritative, Checked::Unchecked, 0));
    }
    let owner = dns("example.com.");
    let records = |class| {
        cache
            .get(&owner, RecordType::A, class, 0)
            .map(|h| h.rrset.rdatas().len())
    };
    assert_eq!((records(Class::IN), records(Class::CH)), (Some(2), Some(1)));
}

#[test]
fn rfc4034_3_group_pairs_signatures_with_the_rrset_they_cover() {
    let message = dnssec::response("alg13_a");
    let sets = Rrset::group(&message.answer);
    let [set] = sets.as_slice() else {
        panic!("one RRset, its RRSIG with it: {sets:?}");
    };
    assert_eq!(set.rtype(), RecordType::A);
    assert_eq!(set.rrsigs().len(), 1);
    let smallest = message.answer.iter().map(|r| r.ttl).min();
    assert_eq!(Some(set.ttl()), smallest);
    // The signature's owner name in another case is the same name (RFC 4343).
    let signatures: Vec<Record<'static>> = message
        .answer
        .iter()
        .filter(|r| r.rtype() == RecordType::RRSIG)
        .cloned()
        .collect();
    let addresses = message
        .answer
        .iter()
        .filter(|r| r.rtype() != RecordType::RRSIG);
    let records: Vec<Record<'static>> = addresses.cloned().chain(shouted(&signatures)).collect();
    assert_eq!(Rrset::group(&records), sets);
}

/// `google.com.`'s first TXT record, its strings edited by `edit`.
fn txt(edit: impl FnOnce(&mut Vec<Vec<u8>>)) -> Record<'static> {
    let record = message(&captured("txt_large")).answer.remove(0);
    let RData::Txt(txt) = record.data() else {
        unreachable!("a TXT record: {record:?}");
    };
    let mut strings: Vec<Vec<u8>> = txt.strings().map(<[u8]>::to_vec).collect();
    edit(&mut strings);
    let txt = Txt::new(strings.iter().map(Vec::as_slice)).expect("the strings of a TXT");
    Record::new(
        record.name.clone(),
        record.class,
        record.ttl,
        &RData::Txt(txt),
    )
}

/// `google.com.`'s first TXT record with its first letter's case flipped.
fn flipped() -> Record<'static> {
    txt(|strings| {
        let letter = strings
            .iter_mut()
            .flatten()
            .find(|b| b.is_ascii_alphabetic())
            .expect("a letter");
        *letter ^= 0x20;
    })
}

/// TXT strings differing in case are other data (RFC 4343 §3: only names fold): `google.com.`'s first TXT record
/// and the same with its first letter's case flipped stay two records, in any order, a duplicate apart dropped.
#[test]
fn rfc4343_3_txt_strings_differing_in_case_stay_two_records() {
    let (record, flipped) = (txt(|_| {}), flipped());
    let [set] = <[Rrset; 1]>::try_from(Rrset::group(&[record.clone(), flipped.clone()]))
        .expect("one RRset");
    assert_eq!(set.rdatas().len(), 2);
    assert_eq!(
        Rrset::group(&[flipped.clone(), record.clone(), flipped]),
        [set]
    );
}

/// RDATA differing in case only is compared among itself: a TXT record and its case variant are not that record
/// and other data of the same count, here sorting after it.
#[test]
fn rfc4343_3_case_variants_are_not_one_of_them_and_other_data() {
    let record = txt(|_| {});
    let longer = txt(|strings| strings.push(b"z".to_vec()));
    let variants = Rrset::group(&[record.clone(), flipped()]);
    let other = Rrset::group(&[record, longer]);
    assert_ne!(variants, other);
    assert_ne!(other, variants);
}

/// Signatures folding the same are told apart by their data: an RRSIG, the same with its signer in capitals (a
/// duplicate, RFC 4343), and one with a letter of its signature flipped (other data), in any order, the duplicate
/// not next to its original.
#[test]
fn rfc4343_rrsigs_differing_in_case_are_duplicates_only_in_their_signer() {
    let message = dnssec::response("alg13_a");
    let (signatures, addresses): (Vec<Record<'static>>, Vec<Record<'static>>) = message
        .answer
        .iter()
        .cloned()
        .partition(|r| r.rtype() == RecordType::RRSIG);
    let [signature] = <[Record<'static>; 1]>::try_from(signatures).expect("one RRSIG");
    let RData::Rrsig(rrsig) = signature.data() else {
        panic!("an RRSIG record: {signature:?}");
    };
    let resigned = |signer: &str, bytes: &[u8]| {
        let rrsig = Rrsig::new(
            rrsig.type_covered,
            rrsig.algorithm,
            rrsig.labels,
            rrsig.original_ttl,
            rrsig.expiration,
            rrsig.inception,
            rrsig.key_tag,
            dns(signer),
            bytes,
        )
        .expect("an RRSIG");
        Record::new(
            signature.name.clone(),
            signature.class,
            signature.ttl,
            &RData::Rrsig(rrsig),
        )
    };
    let signer = rrsig.signer.to_string().to_uppercase();
    let shouted = resigned(&signer, rrsig.signature());
    let mut bytes = rrsig.signature().to_vec();
    let letter = bytes
        .iter_mut()
        .find(|b| b.is_ascii_alphabetic())
        .expect("a letter in the signature");
    *letter ^= 0x20;
    let other = resigned(&signer, &bytes);
    let set = |signatures: &[&Record<'static>]| {
        let records: Vec<Record<'static>> = addresses
            .iter()
            .chain(signatures.iter().copied())
            .cloned()
            .collect();
        let [set] = <[Rrset; 1]>::try_from(Rrset::group(&records)).expect("one RRset");
        set
    };
    let all = set(&[&signature, &other, &shouted]);
    assert_eq!(all.rrsigs().len(), 2);
    assert_eq!(all, set(&[&other, &signature]));
    assert_eq!(all, set(&[&shouted, &other]));
    assert_ne!(all, set(&[&signature, &shouted]));
}

/// A validator caps the TTL to its signature's (RFC 4035 §5.3.3); secure, it has no floor (D124).
#[test]
fn rfc4035_5_3_3_a_secure_rrset_lives_no_longer_than_its_cap() {
    let message = dnssec::response("alg13_a");
    let [mut set] = <[Rrset; 1]>::try_from(Rrset::group(&message.answer)).expect("one RRset");
    let received = set.ttl();
    set.cap_ttl(Ttl::from_wire(u32::MAX >> 1));
    assert_eq!(set.ttl(), received);
    set.cap_ttl(Ttl::from_wire(10));
    assert_eq!(set.ttl().get(), 10);
    let hit = stored(cache().insert(set, Rank::AnswerAuthoritative, Checked::Secure, 0));
    assert_eq!(hit.ttl.get(), 10);
}

#[test]
fn rfc2181_5_2_the_ttl_is_the_smallest_of_the_rrset() {
    let message = message(&captured("a"));
    let mut records = message.answer.clone();
    records[1].ttl = Ttl::from_wire(7);
    let [set] = <[Rrset; 1]>::try_from(Rrset::group(&records)).expect("one RRset");
    assert_eq!(set.ttl().get(), 7);
}

#[test]
fn rfc4343_lookups_ignore_case() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 0));
    let hit = cache.get(&dns("EXAMPLE.Com."), RecordType::A, Class::IN, 0);
    assert_eq!(hit.map(|h| h.rrset.rdatas().len()), Some(2));
    assert_eq!(
        cache.get(&dns("example.com."), RecordType::AAAA, Class::IN, 0),
        None
    );
}

#[test]
fn rfc2181_5_4_1_ranks_are_ordered() {
    assert!(RANKS.is_sorted());
}

/// Each pair of ranks, other data: the higher replaces the lower, the lower leaves the higher. An address replacing
/// glue stays ranked as glue (CVE-2026-42955, below).
#[test]
fn rfc2181_5_4_1_a_higher_rank_replaces_a_lower_one_and_not_the_reverse() {
    for (i, &low) in RANKS.iter().enumerate() {
        for &high in &RANKS[i + 1..] {
            let cache = cache();
            stored(cache.insert(fewer("a", Section::Answer), low, Checked::Unchecked, 0));
            let hit = stored(cache.insert(a(), high, Checked::Unchecked, 1));
            let rank = if low == Rank::AdditionalNonAuthoritative {
                low
            } else {
                high
            };
            assert_eq!(
                (hit.rank, hit.rrset.rdatas().len()),
                (rank, 2),
                "{high:?} over {low:?}"
            );

            let cache = self::cache();
            stored(cache.insert(a(), high, Checked::Unchecked, 0));
            let hit = kept(cache.insert(fewer("a", Section::Answer), low, Checked::Unchecked, 1));
            assert_eq!(
                (hit.rank, hit.rrset.rdatas().len()),
                (high, 2),
                "{low:?} under {high:?}"
            );
            assert_eq!(get(&cache, &a(), 1).map(|h| h.rank), Some(high));
        }
    }
}

#[test]
fn rfc2181_5_4_1_equal_rank_other_data_replaces_same_data_keeps() {
    let cache = cache();
    let first = stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 0));
    // The same data later: the entry stays, its time running.
    let again = kept(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 10));
    assert!(std::sync::Arc::ptr_eq(&first.rrset, &again.rrset));
    assert_eq!(again.ttl.get(), 50);
    // Other data at the same rank: the last heard of.
    let other = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AnswerNonAuthoritative,
        Checked::Unchecked,
        10,
    ));
    assert_eq!((other.rrset.rdatas().len(), other.ttl.get()), (1, 60));
    // Other data of the same size, the first record alone: not the same, so the last heard of again.
    let records = message(&captured("a")).answer;
    let [first] = <[Rrset; 1]>::try_from(Rrset::group(&records[..1])).expect("one RRset");
    let last = stored(cache.insert(
        first.clone(),
        Rank::AnswerNonAuthoritative,
        Checked::Unchecked,
        20,
    ));
    assert_eq!(*last.rrset, first);
    assert_ne!(*last.rrset, *other.rrset);
}

/// The glue of a referral does not replace an answer: `example.com. NS` answered, then from `com`'s referral.
#[test]
fn rfc2181_5_4_1_referral_data_does_not_replace_an_answer() {
    let cache = cache();
    let answer = rrset("ns", Section::Answer);
    stored(cache.insert(
        answer.clone(),
        Rank::AnswerNonAuthoritative,
        Checked::Unchecked,
        0,
    ));
    let referral = rrset("referral_com", Section::Authority);
    assert_eq!(referral, answer, "the same name servers");
    let hit = kept(cache.insert(
        referral,
        Rank::AuthorityNonAuthoritative,
        Checked::Unchecked,
        0,
    ));
    assert_eq!(
        (hit.rank, hit.ttl.get()),
        (Rank::AnswerNonAuthoritative, 81_811)
    );

    let glue = || fewer("a", Section::Answer);
    stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 0));
    for rank in [
        Rank::AdditionalNonAuthoritative,
        Rank::AdditionalAuthoritative,
    ] {
        let hit = kept(cache.insert(glue(), rank, Checked::Unchecked, 0));
        assert_eq!(hit.rrset.rdatas().len(), 2, "{rank:?}");
    }
}

#[test]
fn rfc2181_5_4_1_secure_data_is_trusted_above_any_rank() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AnswerAuthoritative, Checked::Unchecked, 0));
    let hit = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AdditionalNonAuthoritative,
        Checked::Secure,
        0,
    ));
    assert_eq!(
        (hit.checked, hit.rrset.rdatas().len()),
        (Checked::Secure, 1)
    );
    let hit = kept(cache.insert(a(), Rank::AnswerAuthoritative, Checked::Insecure, 0));
    assert_eq!(hit.checked, Checked::Secure);
}

#[test]
fn rfc4035_4_7_bogus_data_gives_way_to_other_data_not_its_own() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, BOGUS, 0));
    // The same data, trusted more: not stored, which would extend the life of bogus data.
    for checked in [Checked::Unchecked, Checked::Insecure] {
        let hit = kept(cache.insert(a(), Rank::AnswerAuthoritative, checked, 0));
        assert_eq!(hit.checked, BOGUS, "{checked:?}");
    }
    let hit = stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Secure, 0));
    assert_eq!(hit.checked, Checked::Secure);

    let cache = self::cache();
    stored(cache.insert(a(), Rank::AnswerAuthoritative, BOGUS, 0));
    // Other data, of a lower rank: stored.
    let hit = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AdditionalNonAuthoritative,
        Checked::Unchecked,
        0,
    ));
    assert_eq!(
        (hit.checked, hit.rank),
        (Checked::Unchecked, Rank::AdditionalNonAuthoritative)
    );
}

#[test]
fn rfc1035_3_2_1_an_expired_rrset_is_replaced_by_anything() {
    let cache = cache();
    // TTL 29, raised to `min_ttl`, 60 (D124).
    stored(cache.insert(a(), Rank::AnswerAuthoritative, Checked::Secure, 0));
    assert_eq!(get(&cache, &a(), 28).map(|h| h.ttl.get()), Some(1));
    assert_eq!(get(&cache, &a(), 29), None);
    let hit = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AdditionalNonAuthoritative,
        BOGUS,
        29,
    ));
    assert_eq!(
        (hit.rank, hit.checked),
        (Rank::AdditionalNonAuthoritative, BOGUS)
    );
}

/// A delegation is not extended past its TTL by data that replaces it (ghost domain names, CVE-2026-40622):
/// `example.com. NS` from `com`'s referral, then answered 100 000 seconds later.
#[test]
fn cve_2026_40622_an_ns_rrset_replacing_one_does_not_extend_its_ttl() {
    let cache = cache();
    let referral = rrset("referral_com", Section::Authority);
    let first = stored(cache.insert(
        referral,
        Rank::AuthorityNonAuthoritative,
        Checked::Unchecked,
        0,
    ));
    assert_eq!(first.ttl.get(), 172_800);
    let answer = rrset("ns", Section::Answer);
    let hit = stored(cache.insert(
        answer,
        Rank::AnswerNonAuthoritative,
        Checked::Unchecked,
        100_000,
    ));
    assert_eq!(
        (hit.rank, hit.ttl.get()),
        (Rank::AnswerNonAuthoritative, 72_800)
    );
    // Other servers, same rank: still the time left.
    let hit = stored(cache.insert(
        fewer("referral_com", Section::Authority),
        Rank::AnswerNonAuthoritative,
        Checked::Unchecked,
        172_000,
    ));
    assert_eq!((hit.rrset.rdatas().len(), hit.ttl.get()), (1, 800));
    // Once expired, the TTL received.
    let hit = stored(cache.insert(
        rrset("ns", Section::Answer),
        Rank::AdditionalNonAuthoritative,
        Checked::Unchecked,
        172_800,
    ));
    assert_eq!(hit.ttl.get(), 81_811);
}

/// Stricter than Unbound, which lets secure data replacing data not secure, and data replacing bogus data, live
/// their own TTL: an NS `RRset` lives no longer than the one it replaces, whatever the verdicts (D193).
#[test]
fn d193_a_secure_ns_rrset_lives_no_longer_than_the_one_it_replaces() {
    // Over bogus data, which lives 60 seconds (D124).
    let cache = cache();
    let bogus = stored(cache.insert(
        rrset("referral_com", Section::Authority),
        Rank::AuthorityNonAuthoritative,
        BOGUS,
        0,
    ));
    assert_eq!(bogus.ttl.get(), 60);
    let hit = stored(cache.insert(
        rrset("ns", Section::Answer),
        Rank::AnswerAuthoritative,
        Checked::Secure,
        10,
    ));
    assert_eq!((hit.checked, hit.ttl.get()), (Checked::Secure, 50));
    // Over data not checked.
    let cache = self::cache();
    stored(cache.insert(
        rrset("referral_com", Section::Authority),
        Rank::AuthorityNonAuthoritative,
        Checked::Unchecked,
        0,
    ));
    let hit = stored(cache.insert(
        fewer("ns", Section::Answer),
        Rank::AnswerAuthoritative,
        Checked::Secure,
        100_000,
    ));
    assert_eq!((hit.checked, hit.ttl.get()), (Checked::Secure, 72_800));
}

/// An answer replacing the glue of a referral lives no longer than the glue had left, and stays ranked as glue, so
/// that another answer does not lengthen it either (CVE-2026-42955): every A and AAAA `RRset` of the root's
/// referral, glue for 172 800 seconds, answered 100 000 seconds later.
#[test]
fn cve_2026_42955_an_address_replacing_glue_does_not_extend_its_ttl() {
    let cache = cache();
    for glue in rrsets("referral_root", Section::Additional) {
        let rtype = glue.rtype();
        stored(cache.insert(
            glue.clone(),
            Rank::AdditionalNonAuthoritative,
            Checked::Unchecked,
            0,
        ));
        let hit = stored(cache.insert(
            glue.clone(),
            Rank::AnswerNonAuthoritative,
            Checked::Unchecked,
            100_000,
        ));
        assert_eq!(
            (hit.rank, hit.ttl.get()),
            (Rank::AdditionalNonAuthoritative, 72_800),
            "{rtype}"
        );
        let hit =
            stored(cache.insert(glue, Rank::AnswerAuthoritative, Checked::Unchecked, 172_000));
        assert_eq!(
            (hit.rank, hit.ttl.get()),
            (Rank::AdditionalNonAuthoritative, 800),
            "{rtype}"
        );
    }
}

/// The glue bound holds for data trusted more than glue, not secure: the additional section of an authoritative
/// answer, as Unbound.
#[test]
fn cve_2026_42955_authoritative_additional_data_replacing_glue_does_not_extend_its_ttl() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0));
    let hit = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AdditionalAuthoritative,
        Checked::Unchecked,
        40,
    ));
    assert_eq!(
        (hit.rank, hit.rrset.rdatas().len(), hit.ttl.get()),
        (Rank::AdditionalNonAuthoritative, 1, 20)
    );
}

/// Other glue replacing glue, trusted the same, takes its own TTL, as Unbound: the bound is for more trust.
#[test]
fn cve_2026_42955_glue_replacing_glue_takes_its_own_ttl() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0));
    let hit = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AdditionalNonAuthoritative,
        Checked::Unchecked,
        10,
    ));
    assert_eq!(hit.ttl.get(), 60);
}

/// The pin holds across the validator's verdict, stricter than Unbound (D193): glue, the same address answered,
/// found insecure (as every answer of an unsigned zone), then other data answered keep the glue's rank and time.
/// A secure verdict lifts it.
#[test]
fn cve_2026_42955_an_insecure_verdict_keeps_an_address_pinned_as_glue() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0));
    let hit = stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 10));
    assert_eq!(
        (hit.rank, hit.ttl.get()),
        (Rank::AdditionalNonAuthoritative, 50)
    );
    let hit = verdict(cache.insert(a(), Rank::AnswerAuthoritative, Checked::Insecure, 20));
    assert_eq!(
        (hit.rank, hit.checked, hit.ttl.get()),
        (Rank::AdditionalNonAuthoritative, Checked::Insecure, 40)
    );
    let hit = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AnswerAuthoritative,
        Checked::Unchecked,
        30,
    ));
    assert_eq!(
        (hit.rank, hit.rrset.rdatas().len(), hit.ttl.get()),
        (Rank::AdditionalNonAuthoritative, 1, 30)
    );

    let cache = self::cache();
    stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0));
    stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 10));
    let hit = verdict(cache.insert(a(), Rank::AnswerAuthoritative, Checked::Secure, 20));
    assert_eq!(
        (hit.rank, hit.checked, hit.ttl.get()),
        (Rank::AnswerAuthoritative, Checked::Secure, 29)
    );
}

/// The pin holds whatever the TTL, stricter than Unbound (D193): an answer shorter than the glue's time left keeps
/// its own TTL but the glue's rank, so that the next answer, other data of equal trust and a longer TTL, lives no
/// longer either. TTLs as received (`min_ttl` 0): 29, and 10 for the short answer.
#[test]
fn cve_2026_42955_a_short_ttl_does_not_unpin_an_address() {
    let config = Config {
        min_ttl: 0,
        ..Config::default()
    };
    let cache = RrsetCache::new(1 << 20, config).expect("a valid config");
    stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0));
    let mut short = fewer("a", Section::Answer);
    short.cap_ttl(Ttl::from_wire(10));
    let hit = stored(cache.insert(short, Rank::AnswerNonAuthoritative, Checked::Unchecked, 5));
    assert_eq!(
        (hit.rank, hit.ttl.get()),
        (Rank::AdditionalNonAuthoritative, 10)
    );
    let hit = stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 6));
    assert_eq!(
        (hit.rank, hit.rrset.rdatas().len(), hit.ttl.get()),
        (Rank::AdditionalNonAuthoritative, 2, 9)
    );
}

/// Secure data replacing glue, and an address replacing data that is not glue, take their own TTL; so do other
/// types replacing glue-ranked data.
#[test]
fn rfc2181_5_4_1_an_address_rrset_replacing_other_than_glue_takes_its_own_ttl() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AdditionalAuthoritative, Checked::Unchecked, 0));
    let hit = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AnswerNonAuthoritative,
        Checked::Unchecked,
        30,
    ));
    assert_eq!(
        (hit.rank, hit.ttl.get()),
        (Rank::AnswerNonAuthoritative, 60)
    );

    let cache = self::cache();
    stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0));
    let hit = stored(cache.insert(
        fewer("a", Section::Answer),
        Rank::AnswerAuthoritative,
        Checked::Secure,
        40,
    ));
    assert_eq!((hit.rank, hit.ttl.get()), (Rank::AnswerAuthoritative, 29));

    let cache = self::cache();
    let mx = || rrset("mx", Section::Answer);
    let first = stored(cache.insert(
        mx(),
        Rank::AdditionalNonAuthoritative,
        Checked::Unchecked,
        0,
    ));
    let hit = stored(cache.insert(mx(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 10));
    assert_eq!(
        (hit.rank, hit.ttl),
        (Rank::AnswerNonAuthoritative, first.ttl)
    );
}

/// A validator records its verdict by inserting the `RRset` again: the same data held unchecked takes it, at any
/// rank, at the greater of the two ranks, living no longer than it had left nor than the verdict allows (D124:
/// 60 seconds bogus, and for TTL 29, 60 insecure, 29 secure).
#[test]
fn d193_a_verdict_on_the_same_data_is_recorded() {
    for (checked, ttl) in [(BOGUS, 50), (Checked::Insecure, 50), (Checked::Secure, 29)] {
        for (rank, held) in [
            (Rank::AnswerNonAuthoritative, Rank::AnswerNonAuthoritative),
            (
                Rank::AdditionalNonAuthoritative,
                Rank::AnswerNonAuthoritative,
            ),
            (Rank::AnswerAuthoritative, Rank::AnswerAuthoritative),
        ] {
            let cache = cache();
            let first =
                stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 0));
            let hit = verdict(cache.insert(a(), rank, checked, 10));
            assert!(std::sync::Arc::ptr_eq(&first.rrset, &hit.rrset));
            assert_eq!(
                (hit.checked, hit.rank, hit.ttl.get()),
                (checked, held, ttl),
                "{checked:?} at {rank:?}"
            );
            assert_eq!(get(&cache, &a(), 10), Some(hit));
            assert_eq!(get(&cache, &a(), 10 + ttl), None);
            // Checked, it is no longer open to a verdict: the same data again is kept.
            kept(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Insecure, 10));
        }
    }
}

/// Another verdict on data checked, or other data, is no verdict: the ranks decide.
#[test]
fn d193_only_unchecked_data_takes_a_verdict() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Insecure, 0));
    let hit = kept(cache.insert(a(), Rank::AnswerNonAuthoritative, BOGUS, 0));
    assert_eq!(hit.checked, Checked::Insecure);
    let cache = self::cache();
    stored(cache.insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 0));
    let hit = kept(cache.insert(
        fewer("a", Section::Answer),
        Rank::AdditionalNonAuthoritative,
        Checked::Insecure,
        0,
    ));
    assert_eq!(hit.checked, Checked::Unchecked);
    // Expired, it is replaced.
    let hit = stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Insecure, 60));
    assert_eq!(
        (hit.rank, hit.checked),
        (Rank::AdditionalNonAuthoritative, Checked::Insecure)
    );
}

#[test]
fn d124_ttls_follow_the_response_cache_config() {
    let config = Config {
        max_ttl: 3600,
        max_insecure_ttl: Some(600),
        bogus_ttl: 30,
        ..Config::default()
    };
    let cache = RrsetCache::new(1 << 20, config).expect("a valid config");
    let ttl = |rrset: Rrset, checked| {
        cache
            .insert(rrset, Rank::AnswerAuthoritative, checked, 0)
            .map(|inserted| inserted.hit().ttl.get())
    };
    // Capped by `max_ttl`, the insecure and the bogus caps.
    let ns = || rrset("referral_root", Section::Authority);
    assert_eq!(ttl(ns(), Checked::Unchecked), Ok(3600));
    let glue = || rrsets("referral_root", Section::Additional);
    assert_eq!(ttl(glue().remove(0), Checked::Insecure), Ok(600));
    assert_eq!(ttl(glue().remove(1), BOGUS), Ok(30));
    // TTL 29 raised to `min_ttl` unless secure: a secure verdict on the same data takes its own.
    assert_eq!(ttl(a(), Checked::Unchecked), Ok(60));
    assert_eq!(ttl(a(), Checked::Secure), Ok(29));
}

#[test]
fn rfc2181_8_ttl_0_and_past_2_pow_31_are_not_cached() {
    let cache = cache();
    stored(cache.insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0));
    for wire in [0, 0x8000_0000, u32::MAX] {
        let message = message(&captured("a"));
        let mut records = message.answer.clone();
        records[0].ttl = Ttl::from_wire(wire);
        let [set] = <[Rrset; 1]>::try_from(Rrset::group(&records)).expect("one RRset");
        assert_eq!(
            cache.insert(set, Rank::AnswerAuthoritative, Checked::Secure, 0),
            Err(NotCached::ZeroTtl),
            "TTL {wire:#x}"
        );
    }
    // The cache is left as it was.
    assert_eq!(
        get(&cache, &a(), 0).map(|h| h.rank),
        Some(Rank::AdditionalNonAuthoritative)
    );
}

/// An entry takes its key (the owner name's wire form, the type and the class) and its `RRset`'s cost: one byte over
/// the entry limit, it is not cached.
#[test]
fn d116_an_rrset_larger_than_an_entry_may_be_is_not_cached() {
    let ns = rrset("referral_root", Section::Authority);
    let entry = ns.owner().wire_len() + 4 + ns.cost();
    for (limit, stored) in [(entry, true), (entry - 1, false)] {
        let config = Config {
            max_entry_bytes: Some(limit),
            ..Config::default()
        };
        let cache = RrsetCache::new(1 << 20, config).expect("a valid config");
        let result = cache.insert(ns.clone(), Rank::AnswerAuthoritative, Checked::Unchecked, 0);
        assert_eq!(result.is_ok(), stored, "limit {limit}");
        assert_eq!(cache.is_empty(), !stored, "limit {limit}");
        if !stored {
            assert_eq!(result, Err(NotCached::TooLarge));
        }
    }
}

#[test]
fn d193_the_default_capacity_is_twice_the_response_cache_s() {
    assert_eq!(DEFAULT_CAPACITY, 2 * Config::default().capacity);
    assert!(RrsetCache::new(DEFAULT_CAPACITY, Config::default()).is_ok());
}

/// The longest owner name, 255 octets, is a key like any other.
#[test]
fn rfc1035_2_3_4_the_longest_owner_name_is_cached() {
    let label = |c: &str, n| c.repeat(n);
    let long = format!(
        "{}.{}.{}.{}.",
        label("a", 63),
        label("b", 63),
        label("c", 63),
        label("d", 61)
    );
    let owner = dns(&long);
    assert_eq!(owner.wire_len(), 255);
    let records: Vec<Record<'static>> = message(&captured("a"))
        .answer
        .iter()
        .map(|r| Record {
            name: owner.clone(),
            ..r.clone()
        })
        .collect();
    let [set] = <[Rrset; 1]>::try_from(Rrset::group(&records)).expect("one RRset");
    let cache = cache();
    stored(cache.insert(set, Rank::AnswerAuthoritative, Checked::Unchecked, 0));
    let upper = dns(&long.to_uppercase());
    assert!(cache.get(&upper, RecordType::A, Class::IN, 0).is_some());
}

/// OPT, the QTYPEs and meta types (128 to 255), type 0 and 65535 are not data: no `RRset` is made of their records.
#[test]
fn rfc6895_3_1_meta_types_make_no_rrset() {
    let message = message(&captured("a"));
    let address = &message.answer[0];
    let data = address.rdata.wire();
    let alone = Rrset::group(std::slice::from_ref(address));
    for rtype in [0, 41, 128, 249, 250, 251, 252, 253, 254, 255, 65535] {
        let rtype = RecordType::from(rtype);
        let opaque = Opaque::new(rtype, &data).expect("RDATA of no typed form");
        let record = Record::new(
            address.name.clone(),
            address.class,
            address.ttl,
            &RData::Opaque(opaque),
        );
        assert_eq!(
            Rrset::group(&[record, address.clone()]),
            alone,
            "type {rtype}"
        );
    }
}

/// Records of the QCLASSes NONE and ANY and of the reserved classes 0 and 65535 make no `RRset`; an unassigned
/// class is data (RFC 6895 §3.2).
#[test]
fn rfc6895_3_2_qclasses_make_no_rrset() {
    let message = message(&captured("a"));
    let address = &message.answer[0];
    let alone = Rrset::group(std::slice::from_ref(address));
    let in_class = |class: u16| Record {
        class: Class::from(class),
        ..address.clone()
    };
    for class in [0, 254, 255, 65535] {
        assert_eq!(
            Rrset::group(&[in_class(class), address.clone()]),
            alone,
            "class {class}"
        );
    }
    assert_eq!(Rrset::group(&[in_class(200)]).len(), 1);
}

#[test]
fn d116_the_capacity_must_hold_an_entry() {
    assert!(matches!(
        RrsetCache::new(1024, Config::default()),
        Err(ConfigError::Capacity(_))
    ));
    let invalid = Config {
        shards: 3,
        ..Config::default()
    };
    assert_eq!(
        RrsetCache::new(1 << 20, invalid).err(),
        Some(ConfigError::Shards(3))
    );
}

/// Every `RRset` of the captures, into a cache of 8 KiB: entries are evicted, the bytes stay within the capacity.
#[test]
fn d116_the_memory_bound_evicts() {
    const CAPACITY: usize = 8 << 10;
    let config = Config {
        shards: 1,
        max_entry_bytes: Some(2048),
        ..Config::default()
    };
    let cache = RrsetCache::new(CAPACITY, config).expect("a valid config");
    let mut stored = 0;
    for case in [
        "referral_root",
        "referral_com",
        "ns",
        "a",
        "aaaa",
        "mx",
        "txt_large",
        "srv",
        "caa",
        "https",
    ] {
        let message = message(&captured(case));
        for (rank, records) in [
            (Rank::AnswerNonAuthoritative, &message.answer),
            (Rank::AuthorityNonAuthoritative, &message.authority),
            (Rank::AdditionalNonAuthoritative, &message.additional),
        ] {
            for set in Rrset::group(records) {
                if cache.insert(set, rank, Checked::Unchecked, 0).is_ok() {
                    stored += 1;
                }
                assert!(cache.used() <= CAPACITY, "{} bytes used", cache.used());
            }
        }
    }
    assert!(
        cache.len() < stored,
        "{} entries of {stored} stored",
        cache.len()
    );
    assert!(cache.used() > CAPACITY / 2, "{} bytes used", cache.used());
    // The last stored is still there.
    let https = rrset("https", Section::Answer);
    assert!(get(&cache, &https, 0).is_some());
}
