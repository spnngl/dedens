//! Targets of dedens-dnssec: the cryptography, `RRset` signatures, denial of existence and the validation of a
//! response, its questions answered from the captured chains.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::LazyLock;

use dedens_dnssec::crypto::{self, Budget};
use dedens_dnssec::denial::{self, MaxIterations};
use dedens_dnssec::rrsig::{self, Key, RrSet, Signature};
use dedens_dnssec::{Limits, Next, TrustAnchors, Validator, Verdict};
use dedens_proto::rdata::RData;
use dedens_proto::{
    DigestType, Message, Name, Nsec3HashAlgorithm, Question, Record, RecordType, SecAlgorithm, Ttl,
    ZoneEntry, ZoneReader,
};

/// The DNSSEC cryptography (D71) on bytes from outside: arbitrary keys, signatures, signed data, digests and
/// salts through `verify`, `key_tag`, `ds_digest` and `nsec3_hash`; and the DNSKEY, RRSIG and DS records of a
/// message, so the captured zones reach the key parsers as real keys. The functions answer with an error on any
/// input, and the policy they state about each algorithm holds.
///
/// # Panics
///
/// On a panic of `dedens-dnssec`, or on an answer that contradicts `supported` or `supported_digest`.
pub fn dnssec_crypto(data: &[u8]) {
    // Bytes as a key, a signature and signed data: the first three octets are the algorithm and two lengths.
    if let [algorithm, key_len, sig_len, rest @ ..] = data {
        let (key, rest) = rest.split_at(usize::from(*key_len).min(rest.len()));
        let (signature, signed) = rest.split_at(usize::from(*sig_len).min(rest.len()));
        verify_checked(SecAlgorithm(*algorithm), key, signed, signature);
        let _ = crypto::key_tag(key);
        let owner: Name<'_> = "Example.COM.".parse().expect("a name");
        for digest in 0..=u8::MAX {
            digest_checked(DigestType(digest), &owner, key);
        }
        let hash = crypto::nsec3_hash(Nsec3HashAlgorithm::SHA1, key, u16::from(*sig_len), &owner);
        assert!(hash.is_ok(), "SHA-1 hashes any salt");
    }
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let records: Vec<&Record<'_>> = [
        &decoded.message.answer,
        &decoded.message.authority,
        &decoded.message.additional,
    ]
    .into_iter()
    .flatten()
    .collect();
    for key in &records {
        let RData::Dnskey(dnskey) = key.data() else {
            continue;
        };
        let mut rdata = dnskey.flags().to_be_bytes().to_vec();
        rdata.extend([3, dnskey.algorithm().into()]);
        rdata.extend(dnskey.public_key());
        let _ = crypto::key_tag(&rdata);
        for other in &records {
            match other.data() {
                RData::Rrsig(rrsig) => verify_checked(
                    dnskey.algorithm(),
                    dnskey.public_key(),
                    &rrsig.signed_rdata(),
                    rrsig.signature(),
                ),
                RData::Ds(ds) => digest_checked(ds.digest_type(), &key.name, &rdata),
                _ => {}
            }
        }
    }
}

/// `verify`, whose `UnsupportedAlgorithm` answer is exactly `supported`'s refusal.
fn verify_checked(algorithm: SecAlgorithm, key: &[u8], signed: &[u8], signature: &[u8]) {
    let answer = crypto::verify(algorithm, key, signed, signature);
    assert_eq!(
        answer == Err(crypto::VerifyError::UnsupportedAlgorithm(algorithm)),
        !crypto::supported(algorithm),
        "{algorithm}"
    );
}

/// `ds_digest`, whose `UnsupportedDigest` answer is exactly `supported_digest`'s refusal.
fn digest_checked(digest: DigestType, owner: &Name<'_>, dnskey_rdata: &[u8]) {
    let answer = crypto::ds_digest(digest, owner, dnskey_rdata);
    assert_eq!(
        answer.as_ref().err() == Some(&crypto::UnsupportedDigest(digest)),
        !crypto::supported_digest(digest),
        "{digest}"
    );
}

/// The `RRset` checks of `dedens_dnssec::rrsig` (D73) on the records of a message: every `RRset` against every
/// RRSIG and DNSKEY the message holds, and every DNSKEY `RRset` against every DS `RRset`, at the time of the
/// first RRSIG's inception (the captured zones verify) and at one taken from the input. Whatever the input, the
/// canonical form is sorted without duplicates, an `RRset` kept for no longer than it came with, an error
/// is never the "unsupported" of a DS (an RRSIG of an unknown algorithm must not make data insecure), and the
/// Extended DNS Error has text.
///
/// # Panics
///
/// On a panic of `dedens-dnssec`, or on an answer that breaks one of those rules.
pub fn rrsig_verify(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let message = &decoded.message;
    let sets: Vec<RrSet<'_>> = [&message.answer, &message.authority, &message.additional]
        .into_iter()
        .flat_map(|section| RrSet::group(section))
        .collect();
    let of_type = |rtype: RecordType| sets.iter().filter(move |set| set.rtype() == rtype);
    let sigs: Vec<Signature<'_>> = of_type(RecordType::RRSIG)
        .flat_map(|set| Signature::all(set))
        .collect();
    let keys: Vec<Key<'_>> = of_type(RecordType::DNSKEY)
        .flat_map(|set| Key::all(set))
        .collect();
    let times = [
        sigs.first().map_or(0, |sig| sig.rrsig().inception),
        data.first_chunk()
            .map_or(0, |bytes| u32::from_be_bytes(*bytes)),
    ];
    for set in &sets {
        let canonical = set.canonical_rdatas();
        assert!(
            canonical.is_sorted_by(|a, b| a < b),
            "canonical RDATA not strictly sorted"
        );
        assert!(canonical.len() <= set.rdatas().len(), "canonical form grew");
        for now in times {
            match rrsig::verify_any(set, &sigs, &keys, now, &mut Budget::default()) {
                Ok(verified) => assert!(verified.ttl <= set.ttl(), "kept longer than it came"),
                Err(error) => {
                    assert!(
                        !error.is_unsupported(),
                        "an RRSIG made data insecure: {error}"
                    );
                    assert!(!error.ede(set).text.is_empty(), "no text for {error}");
                }
            }
            if set.rtype() == RecordType::DNSKEY {
                for ds in of_type(RecordType::DS) {
                    let _ = rrsig::trusted_keys(set, &sigs, ds, now, &mut Budget::default());
                }
            }
        }
    }
}

/// The NSEC and NSEC3 records of a message, or of a zone file, as the proof of denial of existence of a question
/// the message asks, or of a name the records are about: `prove` and `prove_wildcard_answer` under every ancestor
/// of the name as the apex, so that records of any zone, shape and parameters reach every path. Whatever the
/// records, the functions answer, and a proof lasts as long as one of the records does (RFC 9077 §3).
///
/// # Panics
///
/// On a panic of `dedens-dnssec`, or on a proof with a TTL no record has.
pub fn denial(data: &[u8]) {
    let (records, question, labels): (Vec<Record<'static>>, Question<'static>, u8) =
        if let Ok(decoded) = Message::decode(data) {
            let message = decoded.message.into_owned();
            let labels = message
                .answer
                .iter()
                .find_map(|r| match r.data() {
                    RData::Rrsig(rrsig) => Some(rrsig.labels),
                    _ => None,
                })
                .unwrap_or(1);
            let question = message.questions.first().cloned();
            let records = [message.answer, message.authority, message.additional].concat();
            let question = question.or_else(|| {
                records
                    .first()
                    .map(|r| Question::new(r.name.clone(), r.rtype()))
            });
            let Some(question) = question else {
                return;
            };
            (records, question, labels)
        } else {
            let records: Vec<Record<'static>> = ZoneReader::new(data, Some(Name::root()))
                .with_ttl(Ttl::ZERO)
                .filter_map(|entry| match entry {
                    Ok(ZoneEntry::Record(decoded)) => Some(decoded.record),
                    _ => None,
                })
                .collect();
            let Some(first) = records.first() else {
                return;
            };
            // The type is any of those a zone proves things about, picked by the input's length.
            let qtypes = [
                RecordType::A,
                RecordType::MX,
                RecordType::DS,
                RecordType::SOA,
            ];
            let qtype = qtypes[data.len() % qtypes.len()];
            let question = Question::new(first.name.clone(), qtype);
            (records, question, u8::try_from(data.len() % 8).unwrap_or(0))
        };
    let ttls: Vec<Ttl> = records.iter().map(|r| r.ttl).collect();
    let labels_of_name: Vec<&[u8]> = question.name.labels().collect();
    for skip in 0..=labels_of_name.len() {
        let Ok(apex) = Name::from_labels(labels_of_name.iter().skip(skip).copied()) else {
            continue;
        };
        let proofs = [
            denial::prove(
                &apex,
                &question,
                &records,
                MaxIterations::default(),
                &mut Budget::default(),
            ),
            denial::prove_wildcard_answer(
                &apex,
                &question.name,
                labels,
                &records,
                MaxIterations::default(),
                &mut Budget::default(),
            ),
        ];
        for proof in proofs.into_iter().flatten() {
            assert!(
                ttls.contains(&proof.ttl),
                "{proof:?}: no record has the TTL"
            );
        }
    }
}

/// The Unix time of the capture run, "now" for the signatures of the captured seeds.
const CAPTURED_AT: &str = include_str!("../../crates/dedens-dnssec/tests/testdata/captured_at");

/// A captured response, as the bytes it was saved as and as a message.
type Captured = (Vec<u8>, Message<'static>);

/// The captured responses a validation is answered from: the real chains of `tests/testdata/`.
static POOL: LazyLock<Vec<Captured>> = LazyLock::new(|| {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/dedens-dnssec/tests/testdata");
    let mut pool: Vec<Captured> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|entry| std::fs::read(entry.ok()?.path()).ok())
        .filter_map(|wire| {
            let message = Message::decode(&wire).ok()?.message.into_owned();
            Some((wire, message))
        })
        .collect();
    pool.sort_by(|a, b| a.0.cmp(&b.0));
    pool
});

/// `message` as a response to `question`, whatever it answered.
fn answering(message: &Message<'static>, question: &Question<'static>) -> Message<'static> {
    let mut message = message.clone();
    message.questions = vec![question.clone()];
    message
}

/// The captured response to `ask`, when there is one.
fn captured(ask: &Question<'static>) -> Option<&'static Captured> {
    POOL.iter().find(|(_, message)| {
        message
            .questions
            .first()
            .is_some_and(|q| q.name == ask.name && q.qtype == ask.qtype)
    })
}

/// A response read from the input, validated, its questions answered from the captured chains: each answer is
/// picked by a byte of the input, as the input's own message, none, the captured response to the question, that
/// response with a bit of it flipped, or a captured response to another question. Whatever the bytes, the
/// validation asks only for DS and DNSKEY, asks at most the limit, ends, and a verdict that is not secure and has
/// an extended error gives it text. The validator is new for each input, so that no input depends on another
/// through its key cache, and the validation runs twice on it, the second with what the first cached.
///
/// # Panics
///
/// On a panic of `dedens-dnssec`, or on a validation that breaks one of those rules.
pub fn validate(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let response = decoded.message.into_owned();
    let Some(question) = response.questions.first().cloned() else {
        return;
    };
    let now = CAPTURED_AT.trim().parse().unwrap_or(0);
    let validator = Validator::new(TrustAnchors::root(), Limits::default());
    let first = validate_once(&validator, data, &response, &question, now);
    let second = validate_once(&validator, data, &response, &question, now);
    // Same answers, so the same verdict, from the cache or not (what is indeterminate says nothing, and the
    // second run has the budget and the questions the first spent); the TTL of a hit is what is left.
    if !matches!(first, Verdict::Indeterminate { .. })
        && !matches!(second, Verdict::Indeterminate { .. })
    {
        assert_eq!(
            (
                std::mem::discriminant(&first),
                first.ede().map(|ede| ede.code)
            ),
            (
                std::mem::discriminant(&second),
                second.ede().map(|ede| ede.code)
            ),
            "the second validation differs: {first:?}, then {second:?}"
        );
    }
}

/// One validation of `response` with `validator`, answered as `validate` says, and its verdict. The answer to a
/// question is picked by the question, not by when it is asked, so that a run that asks fewer (the cache has the
/// keys) gets the answers of the one before.
fn validate_once(
    validator: &Validator,
    data: &[u8],
    response: &Message<'static>,
    question: &Question<'static>,
    now: u64,
) -> Verdict {
    let limit = Limits::default().questions;
    let mut validation = validator.start(question, response, now);
    for asked in 0..=limit {
        match validation.step() {
            Next::Ask(ask) => {
                assert!(
                    matches!(ask.qtype, RecordType::DS | RecordType::DNSKEY),
                    "asked for {}",
                    ask.qtype
                );
                assert!(asked < limit, "asked past the limit");
                let slot = {
                    let mut hasher = DefaultHasher::new();
                    (&ask.name, ask.qtype).hash(&mut hasher);
                    usize::try_from(hasher.finish() % 4096).unwrap_or(0)
                };
                let pick = data
                    .get(slot % data.len().saturating_sub(12).max(1) + 12)
                    .copied()
                    .unwrap_or(2);
                let answer = match pick % 5 {
                    0 => None,
                    1 => Some(answering(response, &ask)),
                    2 => captured(&ask).map(|(_, message)| message.clone()),
                    3 => captured(&ask).and_then(|(wire, _)| {
                        let mut wire = wire.clone();
                        let at = usize::from(pick).saturating_mul(slot + 7) % wire.len().max(1);
                        *wire.get_mut(at)? ^= 1 << (pick % 8);
                        Some(Message::decode(&wire).ok()?.message.into_owned())
                    }),
                    _ => POOL
                        .get(usize::from(pick) % POOL.len().max(1))
                        .map(|(_, message)| answering(message, &ask)),
                };
                validation.answer(answer.as_ref());
            }
            Next::Done(verdict) => {
                if let Some(ede) = verdict.ede() {
                    assert!(!ede.text.is_empty(), "no text for {verdict:?}");
                }
                return verdict;
            }
        }
    }
    unreachable!("a validation asks at most the limit, then ends");
}
