//! The root's trust anchors followed through its KSK rollover by RFC 5011 (D200), over the root's DNSKEY `RRset`s
//! of the KSK-2010 (19036) to KSK-2017 (20326) rollover.
//!
//! - RFC 5011 §2.1: a key's revocation, signed by itself, makes it no anchor, for good: it is kept after the remove
//!   hold-down (§2.4.2), which a resolver may take to forget it, against an anchor it is seeded with.
//! - RFC 5011 §2.2 and §2.4.1: a new key is trusted only once seen after the add hold-down, and dropped when gone
//!   before.
//! - RFC 5011 §2.3: the wait before the next query, half the `RRset`'s TTL.
//! - RFC 5011 §4: the states and their events; a missing key stays trusted, until the keep-missing time.
//!
//! The `RRset`s are those of the root zone the Internet Archive kept, as `just capture-rollover` fetched them in
//! `testdata/dnssec/rollover-*.zone`, each named by its capture time; the time is set by each test inside the window of
//! the snapshot's signatures.

use std::fs;

use dedens_dnssec::crypto::key_tag;
use dedens_dnssec::rrsig::SigError;
use dedens_dnssec::{KeyState, Rollover, RolloverError, TrustAnchors};
use dedens_proto::rdata::{Dnskey, RData};
use dedens_proto::{Name, Record, ZoneEntry, ZoneReader};

/// The root's DS record of KSK-2010, as IANA's `root-anchors.xml` lists it.
const DS_2010: &str =
    ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5\n";
/// The root's DS record of KSK-2017, as IANA's `root-anchors.xml` lists it.
const DS_2017: &str =
    ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n";

/// 2017-06-15 12:00 UTC: KSK-2010 alone.
const JUNE_2017: u64 = 1_497_528_000;
/// 2017-07-16 12:00 UTC: KSK-2017 published.
const JULY_2017: u64 = 1_500_206_400;
/// 2017-08-12 12:00 UTC: three days before the hold-down of KSK-2017 ends.
const AUGUST_12_2017: u64 = 1_502_539_200;
/// 2017-08-16 12:00 UTC: a day after it ends.
const AUGUST_16_2017: u64 = 1_502_884_800;
/// 2017-08-30 12:00 UTC: 12 hours before the signatures of the August 2017 `RRset` end.
const AUGUST_30_2017: u64 = 1_504_094_400;
/// 2018-12-25 12:00 UTC: both keys, KSK-2017 signing.
const DECEMBER_2018: u64 = 1_545_739_200;
/// 2019-03-05 12:00 UTC: KSK-2010 revoked.
const MARCH_2019: u64 = 1_551_787_200;
/// 2019-04-02 12:00 UTC: KSK-2010 gone, 28 days after its revocation was seen.
const APRIL_2_2019: u64 = 1_554_206_400;
/// 2019-04-10 12:00 UTC: 36 days after.
const APRIL_10_2019: u64 = 1_554_897_600;

/// A day, in seconds.
const DAY: u64 = 86_400;

/// The records of the snapshot captured at `at`.
fn snapshot(at: &str) -> Vec<Record<'static>> {
    let text = fs::read_to_string(dedens_testkit::path(&format!("dnssec/rollover-{at}.zone")))
        .expect("a captured snapshot");
    ZoneReader::new(text.as_bytes(), None)
        .map(|entry| match entry.expect("zone text") {
            ZoneEntry::Record(decoded) => decoded.record,
            other => unreachable!("not a record: {other:?}"),
        })
        .collect()
}

fn june_2017() -> Vec<Record<'static>> {
    snapshot("20170615085551")
}
fn july_2017() -> Vec<Record<'static>> {
    snapshot("20170716113230")
}
fn august_2017() -> Vec<Record<'static>> {
    snapshot("20170816120412")
}
fn december_2018() -> Vec<Record<'static>> {
    snapshot("20181224040024")
}
fn march_2019() -> Vec<Record<'static>> {
    snapshot("20190305003355")
}
fn april_2019() -> Vec<Record<'static>> {
    snapshot("20190406221638")
}

fn anchors(text: &str) -> TrustAnchors {
    TrustAnchors::read(text).expect("anchor text")
}

/// The root's DNSKEY of `records` whose key tag is `tag`.
fn dnskey(records: &[Record<'_>], tag: u16) -> Dnskey<'static> {
    records
        .iter()
        .find(|record| key_tag(&record.rdata.wire()) == tag)
        .and_then(|record| match record.data() {
            RData::Dnskey(key) => Some(key.into_owned()),
            _ => None,
        })
        .expect("the key of that tag")
}

/// The key tag and state of each key `rollover` follows, by tag.
fn states(rollover: &Rollover) -> Vec<(u16, KeyState)> {
    let mut states: Vec<_> = rollover
        .keys()
        .map(|(key, state)| {
            let mut wire = key.flags().to_be_bytes().to_vec();
            wire.extend_from_slice(&[3, u8::from(key.algorithm())]);
            wire.extend_from_slice(key.public_key());
            (key_tag(&wire), state)
        })
        .collect();
    states.sort_unstable_by_key(|&(tag, _)| tag);
    states
}

/// The key tags of the root's DNSKEY anchors of `rollover`.
fn trusted(rollover: &Rollover) -> Vec<u16> {
    let Some(anchors) = rollover.anchors() else {
        return Vec::new();
    };
    let (_, anchor) = anchors.closest(&Name::root()).expect("a root anchor");
    assert!(anchor.ds().is_empty(), "DNSKEY anchors only");
    let mut tags: Vec<_> = anchor
        .dnskeys()
        .iter()
        .map(|key| {
            let mut wire = key.flags().to_be_bytes().to_vec();
            wire.extend_from_slice(&[3, u8::from(key.algorithm())]);
            wire.extend_from_slice(key.public_key());
            key_tag(&wire)
        })
        .collect();
    tags.sort_unstable();
    tags
}

/// Both keys valid, seeded from both DS records in December 2018.
fn both_valid() -> Rollover {
    let (rollover, _) = Rollover::seed(
        &anchors(&format!("{DS_2010}{DS_2017}")),
        &december_2018(),
        DECEMBER_2018,
    )
    .expect("seeded");
    assert_eq!(
        states(&rollover),
        [(19036, KeyState::Valid), (20326, KeyState::Valid)]
    );
    rollover
}

// --- RFC 5011 §2.2 and §2.4.1: the add hold-down ---

#[test]
fn rfc5011_s2_2_new_key_trusted_after_the_add_hold_down() {
    let (mut rollover, wait) =
        Rollover::seed(&anchors(DS_2010), &june_2017(), JUNE_2017).expect("seeded");
    assert_eq!(states(&rollover), [(19036, KeyState::Valid)]);
    // RFC 5011 §2.3: half the TTL of 2 days.
    assert_eq!(wait, DAY);

    rollover.observe(&july_2017(), JULY_2017).expect("observed");
    let until = JULY_2017 + Rollover::ADD_HOLD_DOWN;
    assert_eq!(
        states(&rollover),
        [
            (19036, KeyState::Valid),
            (20326, KeyState::AddPend { until })
        ]
    );
    assert_eq!(trusted(&rollover), [19036]);

    rollover
        .observe(&august_2017(), AUGUST_12_2017)
        .expect("observed");
    assert_eq!(trusted(&rollover), [19036], "the hold-down is not over");

    rollover
        .observe(&august_2017(), AUGUST_16_2017)
        .expect("observed");
    assert_eq!(
        states(&rollover),
        [(19036, KeyState::Valid), (20326, KeyState::Valid)]
    );
    assert_eq!(trusted(&rollover), [19036, 20326]);
}

/// RFC 5011 §2.3: half the seconds left to the signatures' end, 6 hours, is raised to 12 hours.
#[test]
fn rfc5011_s2_3_the_wait_is_at_least_twelve_hours() {
    let (_, wait) =
        Rollover::seed(&anchors(DS_2010), &august_2017(), AUGUST_30_2017).expect("seeded");
    assert_eq!(wait, 12 * 60 * 60);
}

/// The root's keys are the DNSKEY `RRset` at the root: `com`'s, captured, ahead of it is not taken.
#[test]
fn rfc5011_s4_the_keys_followed_are_the_roots() {
    let wire = fs::read(dedens_testkit::path("dnssec/com_dnskey.bin")).expect("captured");
    let mixed: Vec<_> = (dedens_testkit::message(&wire).answer.into_iter())
        .chain(june_2017())
        .collect();
    let (rollover, _) = Rollover::seed(&anchors(DS_2010), &mixed, JUNE_2017).expect("seeded");
    assert_eq!(states(&rollover), [(19036, KeyState::Valid)]);
}

#[test]
fn rfc5011_s4_pending_key_gone_is_dropped() {
    let text = format!(
        "dedens rfc5011 1\nvalid {}\naddpend {} {}\nend\n",
        dnskey(&july_2017(), 19036),
        AUGUST_16_2017,
        dnskey(&july_2017(), 20326),
    );
    let mut rollover = Rollover::read(&text).expect("state text");
    rollover.observe(&june_2017(), JUNE_2017).expect("observed");
    assert_eq!(states(&rollover), [(19036, KeyState::Valid)]);
}

// --- RFC 5011 §2.1 and §2.4.2: revocation and the remove hold-down ---

#[test]
fn rfc5011_s2_1_revoked_key_is_no_anchor_and_stays_revoked() {
    let mut rollover = both_valid();
    rollover
        .observe(&march_2019(), MARCH_2019)
        .expect("observed");
    assert_eq!(
        states(&rollover),
        [
            (19036, KeyState::Revoked { seen: MARCH_2019 }),
            (20326, KeyState::Valid)
        ]
    );
    assert_eq!(trusted(&rollover), [20326]);

    // Past the remove hold-down, no longer published: still revoked, so that no seed trusts it again.
    rollover
        .observe(&april_2019(), APRIL_10_2019)
        .expect("observed");
    assert_eq!(
        states(&rollover),
        [
            (19036, KeyState::Revoked { seen: MARCH_2019 }),
            (20326, KeyState::Valid)
        ]
    );
}

#[test]
fn rfc5011_s2_1_revocation_kept_when_nothing_else_signs() {
    // Only KSK-2010 trusted: its revocation is signed by itself, the RRset by KSK-2017, which is not trusted.
    let text = format!(
        "dedens rfc5011 1\nvalid {}\nend\n",
        dnskey(&december_2018(), 19036)
    );
    let mut rollover = Rollover::read(&text).expect("state text");
    assert!(matches!(
        rollover.observe(&march_2019(), MARCH_2019),
        Err(RolloverError::Unverified(_))
    ));
    assert_eq!(
        states(&rollover),
        [(19036, KeyState::Revoked { seen: MARCH_2019 })]
    );
    assert_eq!(rollover.anchors(), None, "the caller's other anchors hold");
}

/// The key signing `com`'s DNSKEY `RRset`, captured: a key valid in a state that signs nothing of the root's.
fn com_ksk() -> Dnskey<'static> {
    let wire = fs::read(dedens_testkit::path("dnssec/com_dnskey.bin")).expect("captured");
    dedens_testkit::message(&wire)
        .answer
        .iter()
        .find_map(|record| match record.data() {
            RData::Dnskey(key) if key.is_secure_entry_point() => Some(key.into_owned()),
            _ => None,
        })
        .expect("com's KSK")
}

/// A state that holds the revoked KSK-2010 and a valid key that signs nothing of the root's, which no answer of
/// the root's verifies.
fn revoked_2010_beside_another_key() -> Rollover {
    let text = format!(
        "dedens rfc5011 1\nrevoked {MARCH_2019} {}\nvalid {}\nend\n",
        dnskey(&december_2018(), 19036),
        com_ksk(),
    );
    Rollover::read(&text).expect("state text")
}

/// RFC 5011 §2.1 and §4: a revoked key is never a trust anchor again. A state that no answer verifies is replaced by
/// the anchors it is seeded with, which may predate the revocation (a stale download keeps the DS of KSK-2010): the
/// revocation is carried over, and an `RRset` KSK-2010 alone signs, as an attacker holding it serves, is not
/// verified through that DS.
#[test]
fn rfc5011_s2_1_a_revoked_key_is_not_trusted_again_by_a_reseed() {
    let stale = anchors(&format!("{DS_2010}{DS_2017}"));
    let state = revoked_2010_beside_another_key();
    assert!(matches!(
        state.clone().observe(&december_2018(), DECEMBER_2018),
        Err(RolloverError::Unverified(_))
    ));
    let (reseeded, _) = state
        .reseed(&stale, &december_2018(), DECEMBER_2018)
        .expect("KSK-2017 signs and its DS is trusted");
    assert_eq!(
        states(&reseeded),
        [
            (19036, KeyState::Revoked { seen: MARCH_2019 }),
            (20326, KeyState::Valid)
        ]
    );
    assert_eq!(trusted(&reseeded), [20326]);

    // DNSKEY anchors of the revoked key are no more trusted than its DS.
    let key = dnskey(&december_2018(), 19036);
    let dnskey_anchors = anchors(&format!(". IN DNSKEY {key}\n{DS_2017}"));
    let (reseeded, _) = state
        .reseed(&dnskey_anchors, &december_2018(), DECEMBER_2018)
        .expect("reseeded");
    assert_eq!(trusted(&reseeded), [20326]);

    // Only the revoked key's DS: nothing verifies, the revocation stays.
    assert!(matches!(
        state.reseed(&anchors(DS_2010), &december_2018(), DECEMBER_2018),
        Err(RolloverError::Unverified(_))
    ));
}

/// RFC 5011 §2.1: a state of revoked keys only is read, trusts nothing, and takes the revoked keys out of other
/// anchors, the DS of a revoked key and a DNSKEY, whatever form of it.
#[test]
fn rfc5011_s2_1_revoked_keys_alone_are_a_state_that_filters_other_anchors() {
    let k2010 = dnskey(&december_2018(), 19036);
    let text = format!("dedens rfc5011 1\nrevoked {MARCH_2019} {k2010}\nend\n");
    let state = Rollover::read(&text).expect("a state of a revoked key");
    assert_eq!(state.to_string(), text);
    assert_eq!(state.anchors(), None);
    let both = anchors(&format!("{DS_2010}{DS_2017}. IN DNSKEY {k2010}\n"));
    assert_eq!(state.without_revoked(&both), anchors(DS_2017));
    assert_eq!(state.without_revoked(&anchors(DS_2017)), anchors(DS_2017));
    // Nothing is left to trust, not an absent anchor, which would leave the root insecure.
    let left = state.without_revoked(&anchors(DS_2010));
    let (_, left) = left
        .closest(&Name::root())
        .expect("the root's anchor stays");
    assert_eq!((left.ds().len(), left.dnskeys().len()), (0, 0));
}

// --- RFC 5011 §4: missing keys ---

#[test]
fn rfc5011_s4_missing_key_stays_trusted() {
    let mut rollover = both_valid();
    rollover
        .observe(&april_2019(), APRIL_2_2019)
        .expect("observed");
    assert_eq!(
        states(&rollover),
        [
            (
                19036,
                KeyState::Missing {
                    since: APRIL_2_2019
                }
            ),
            (20326, KeyState::Valid)
        ]
    );
    assert_eq!(trusted(&rollover), [19036, 20326]);
}

#[test]
fn rfc5011_s4_missing_key_seen_again_is_valid() {
    let text = format!(
        "dedens rfc5011 1\nmissing {} {}\nvalid {}\nend\n",
        DECEMBER_2018 - DAY,
        dnskey(&december_2018(), 19036),
        dnskey(&december_2018(), 20326),
    );
    let mut rollover = Rollover::read(&text).expect("state text");
    rollover
        .observe(&december_2018(), DECEMBER_2018)
        .expect("observed");
    assert_eq!(
        states(&rollover),
        [(19036, KeyState::Valid), (20326, KeyState::Valid)]
    );
}

#[test]
fn rfc5011_s4_missing_key_dropped_after_keep_missing() {
    let since = APRIL_10_2019 - 366 * DAY - 1;
    let text = format!(
        "dedens rfc5011 1\nmissing {since} {}\nvalid {}\nend\n",
        dnskey(&december_2018(), 19036),
        dnskey(&december_2018(), 20326),
    );
    let mut rollover = Rollover::read(&text).expect("state text");
    rollover
        .observe(&april_2019(), APRIL_2_2019)
        .expect("observed");
    assert_eq!(
        states(&rollover),
        [
            (19036, KeyState::Missing { since }),
            (20326, KeyState::Valid)
        ],
        "missing for less than a year"
    );
    rollover
        .observe(&april_2019(), APRIL_10_2019)
        .expect("observed");
    assert_eq!(states(&rollover), [(20326, KeyState::Valid)]);
}

// --- RFC 5011 §4 and RFC 4035 §5.3: an RRset no trusted key signs ---

#[test]
fn rfc5011_s4_rrset_not_signed_by_a_trusted_key_changes_nothing() {
    // KSK-2017 alone trusted; the June 2017 RRset is signed by KSK-2010 and lacks KSK-2017.
    let text = format!(
        "dedens rfc5011 1\nvalid {}\nend\n",
        dnskey(&july_2017(), 20326)
    );
    let mut rollover = Rollover::read(&text).expect("state text");
    let before = rollover.clone();
    assert!(matches!(
        rollover.observe(&june_2017(), JUNE_2017),
        Err(RolloverError::Unverified(SigError::NoKey {
            key_tag: 19036
        }))
    ));
    assert_eq!(rollover, before);
    assert!(matches!(
        Rollover::seed(&anchors(DS_2017), &june_2017(), JUNE_2017),
        Err(RolloverError::Unverified(_))
    ));
}

#[test]
fn rfc5011_s4_rrset_out_of_its_signature_window_changes_nothing() {
    let mut rollover = both_valid();
    let before = rollover.clone();
    assert!(matches!(
        rollover.observe(&march_2019(), APRIL_10_2019),
        Err(RolloverError::Unverified(SigError::Expired { .. }))
    ));
    assert_eq!(rollover, before);
    assert_eq!(
        rollover.observe(&[], APRIL_10_2019),
        Err(RolloverError::NoKeys)
    );
}

// --- Seeding (D200): DNSKEY anchors, and agreement with other anchors ---

#[test]
fn rfc5011_s4_seed_from_a_dnskey_anchor() {
    let key = dnskey(&december_2018(), 20326);
    let (rollover, _) = Rollover::seed(
        &anchors(&format!(". IN DNSKEY {key}\n")),
        &december_2018(),
        DECEMBER_2018,
    )
    .expect("seeded");
    assert_eq!(
        states(&rollover),
        [
            (
                19036,
                KeyState::AddPend {
                    until: DECEMBER_2018 + Rollover::ADD_HOLD_DOWN
                }
            ),
            (20326, KeyState::Valid)
        ]
    );
    assert!(!rollover.agrees(&anchors(&format!("{DS_2010}{DS_2017}"))));
    assert!(rollover.agrees(&anchors(DS_2017)));
    assert!(rollover.agrees(&anchors(&format!(". IN DNSKEY {key}\n"))));
}

#[test]
fn rfc5011_s4_agrees_with_the_anchors_of_the_same_keys() {
    let rollover = both_valid();
    assert!(rollover.agrees(&anchors(&format!("{DS_2010}{DS_2017}"))));
    assert!(!rollover.agrees(&anchors(DS_2017)));
    assert!(!rollover.agrees(&anchors("example. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n")));
}

// --- The state text (D200) ---

/// The records of an `RRset` come in any order (RFC 2181 §5): the state text is the same, and reads back.
#[test]
fn rfc5011_state_text_is_in_the_keys_order() {
    let ds = anchors(&format!("{DS_2010}{DS_2017}"));
    let mut reversed = december_2018();
    reversed.reverse();
    let (sorted, _) = Rollover::seed(&ds, &december_2018(), DECEMBER_2018).expect("seeded");
    let (rollover, _) = Rollover::seed(&ds, &reversed, DECEMBER_2018).expect("seeded");
    assert_eq!(rollover.to_string(), sorted.to_string());
    assert_eq!(Rollover::read(&rollover.to_string()), Ok(rollover));
}

#[test]
fn rfc5011_state_text_reads_back() {
    let mut rollover = both_valid();
    rollover
        .observe(&march_2019(), MARCH_2019)
        .expect("observed");
    let text = rollover.to_string();
    assert!(
        text.starts_with("dedens rfc5011 1\nrevoked 1551787200 257 3 8 "),
        "{text}"
    );
    assert_eq!(Rollover::read(&text), Ok(rollover));
}

#[test]
fn rfc5011_state_text_cut_short_is_refused() {
    let mut rollover = both_valid();
    rollover
        .observe(&march_2019(), MARCH_2019)
        .expect("observed");
    let text = rollover.to_string();
    for end in (0..text.len()).filter(|&end| text.is_char_boundary(end)) {
        assert!(
            Rollover::read(&text[..end]).is_err(),
            "read cut at {end}: {:?}",
            &text[..end]
        );
    }
}

#[test]
fn rfc5011_state_text_refused() {
    let k2010 = dnskey(&december_2018(), 19036);
    let k2017 = dnskey(&december_2018(), 20326);
    let revoked = dnskey(&march_2019(), 19164);
    let refused = [
        // Trusts nothing.
        format!("dedens rfc5011 1\naddpend 1 {k2010}\nend\n"),
        "dedens rfc5011 1\nend\n".to_owned(),
        // Out of order, twice.
        format!("dedens rfc5011 1\nvalid {k2017}\nvalid {k2010}\nend\n"),
        format!("dedens rfc5011 1\nvalid {k2010}\nvalid {k2010}\nend\n"),
        // A revoked key, a time where none is, none where one is, a sign, an unknown state.
        format!("dedens rfc5011 1\nvalid {revoked}\nend\n"),
        format!("dedens rfc5011 1\nvalid 1 {k2010}\nend\n"),
        format!("dedens rfc5011 1\nmissing {k2010}\nend\n"),
        format!("dedens rfc5011 1\nmissing +1 {k2010}\nend\n"),
        format!("dedens rfc5011 1\nstart 1 {k2010}\nend\n"),
        // Not as written: a blank, a comment, another header, after `end`.
        format!("dedens rfc5011 1\nvalid  {k2010}\nend\n"),
        format!("dedens rfc5011 1\nvalid {k2010} ; KSK-2010\nend\n"),
        format!("dedens rfc5011 2\nvalid {k2010}\nend\n"),
        format!("dedens rfc5011 1\nvalid {k2010}\nend\n\n"),
        format!("dedens rfc5011 1\nvalid {k2010}\nend\nvalid {k2017}\n"),
    ];
    for text in refused {
        assert!(Rollover::read(&text).is_err(), "read: {text}");
    }
    let long = format!(
        "dedens rfc5011 1\n{}valid {k2010}\nend\n",
        "x".repeat(Rollover::MAX_LEN)
    );
    assert_eq!(
        Rollover::read(&long).map_err(|error| (error.line, error.what)),
        Err((0, "longer than 64 KiB"))
    );
    // 64 KiB is read, to what it lacks.
    let full = format!("{long:.65535}\n");
    assert_eq!(full.len(), 64 << 10);
    assert_eq!(
        Rollover::read(&full).map_err(|error| (error.line, error.what)),
        Err((0, "no `end` line at the end"))
    );
}
