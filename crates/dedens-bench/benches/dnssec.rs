//! DNSSEC crypto (D71): one signature verification per validated algorithm and key size, on the RFC examples the
//! tests verify (their keys and signatures are in `dedens_testkit::dnssec`), the DS digests and the NSEC3
//! hash. The numbers size `Budget`'s defaults (`docs/benchmarks.md`).

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};

use dedens_dnssec::crypto::{Budget, ds_digest, nsec3_hash, verify};
use dedens_dnssec::rrsig::{self, Key, RrSet, Signature};
use dedens_dnssec::{Limits, Next, TrustAnchors, Validator, Verdict};
use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::{
    DigestType, Message, Name, Nsec3HashAlgorithm, RecordType, SecAlgorithm, Transport,
};
use dedens_server::{
    Allowance, Budget as Share, Budgets, DEFAULT_SHARE, Forward, MAX_BUDGET, Pipeline, Stage, Step,
    Validating,
};
use dedens_testkit::dns;
use dedens_testkit::dnssec::{
    ED25519_KEY_1, ED25519_SIGNATURE_1, P256_KEY, P256_SIGNATURE, P384_KEY, P384_SIGNATURE,
    RFC4035_NS1_SIGNATURE, RFC4035_ZSK, Rr, Rrsig, SHA512_KEY, SHA512_SIGNATURE,
    URI_DNSKEY_SIGNATURE, URI_KSK_1, URI_KSK_2, URI_MX_SIGNATURE, URI_ZSK, b64, canonical_name,
    captured_at, dnskey_rdata, names, response, signed_data,
};

fn main() {
    divan::main();
}

/// What one verification takes: the algorithm, the key, the signed data and the signature.
struct Case {
    algorithm: SecAlgorithm,
    key: Vec<u8>,
    signed: Vec<u8>,
    signature: Vec<u8>,
}

fn rrsig(
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    key_tag: u16,
    signer: &str,
    window: (u32, u32),
) -> Rrsig<'_> {
    Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration: window.1,
        inception: window.0,
        key_tag,
        signer,
    }
}

fn a_record(owner: &str) -> Rr<'_> {
    Rr {
        owner,
        rdata: vec![192, 0, 2, 1],
    }
}

fn mx_record<'a>(owner: &'a str, exchange: &str) -> Rr<'a> {
    let mut rdata = 10_u16.to_be_bytes().to_vec();
    rdata.extend(canonical_name(exchange));
    Rr { owner, rdata }
}

fn case(algorithm: SecAlgorithm, key: &str, signed: Vec<u8>, signature: &str) -> Case {
    Case {
        algorithm,
        key: b64(key),
        signed,
        signature: b64(signature),
    }
}

fn rsasha1_1024() -> Case {
    let sig = rrsig(
        1,
        5,
        2,
        3600,
        38519,
        "example.",
        (1_081_535_779, 1_084_127_779),
    );
    case(
        SecAlgorithm::RSASHA1,
        RFC4035_ZSK,
        signed_data(&sig, &[a_record("ns1.example.")]),
        RFC4035_NS1_SIGNATURE,
    )
}

fn rsasha256_1024() -> Case {
    let sig = rrsig(
        15,
        8,
        2,
        600,
        37444,
        "uri.arpa.",
        (1_611_185_080, 1_613_604_280),
    );
    let rrset = [mx_record("uri.arpa.", "pechora.icann.org.")];
    case(
        SecAlgorithm::RSASHA256,
        URI_ZSK,
        signed_data(&sig, &rrset),
        URI_MX_SIGNATURE,
    )
}

/// The DNSKEY `RRset` of three keys, signed by the KSK of key tag 12670.
fn rsasha256_2048() -> Case {
    let sig = rrsig(
        48,
        8,
        2,
        3600,
        12670,
        "uri.arpa.",
        (1_611_185_080, 1_613_604_280),
    );
    let rrset = [
        dnskey_rdata(256, 8, URI_ZSK),
        dnskey_rdata(257, 8, URI_KSK_1),
        dnskey_rdata(257, 8, URI_KSK_2),
    ]
    .map(|rdata| Rr {
        owner: "uri.arpa.",
        rdata,
    });
    let signer = [URI_KSK_1, URI_KSK_2]
        .into_iter()
        .find(|key| dedens_dnssec::crypto::key_tag(&dnskey_rdata(257, 8, key)) == 12670)
        .expect("one KSK signed");
    case(
        SecAlgorithm::RSASHA256,
        signer,
        signed_data(&sig, &rrset),
        URI_DNSKEY_SIGNATURE,
    )
}

fn rsasha512_1024() -> Case {
    let sig = rrsig(
        1,
        10,
        3,
        3600,
        3740,
        "example.net.",
        (946_684_800, 1_893_456_000),
    );
    let record = Rr {
        owner: "www.example.net.",
        rdata: vec![192, 0, 2, 91],
    };
    case(
        SecAlgorithm::RSASHA512,
        SHA512_KEY,
        signed_data(&sig, &[record]),
        SHA512_SIGNATURE,
    )
}

fn p256() -> Case {
    let sig = rrsig(
        1,
        13,
        3,
        3600,
        55648,
        "example.net.",
        (1_281_607_479, 1_284_026_679),
    );
    case(
        SecAlgorithm::ECDSAP256SHA256,
        P256_KEY,
        signed_data(&sig, &[a_record("www.example.net.")]),
        P256_SIGNATURE,
    )
}

fn p384() -> Case {
    let sig = rrsig(
        1,
        14,
        3,
        3600,
        10771,
        "example.net.",
        (1_281_608_425, 1_284_027_625),
    );
    case(
        SecAlgorithm::ECDSAP384SHA384,
        P384_KEY,
        signed_data(&sig, &[a_record("www.example.net.")]),
        P384_SIGNATURE,
    )
}

fn ed25519() -> Case {
    let sig = rrsig(
        15,
        15,
        3,
        3600,
        3613,
        "example.com.",
        (1_438_207_200, 1_440_021_600),
    );
    case(
        SecAlgorithm::ED25519,
        ED25519_KEY_1,
        signed_data(&sig, &[mx_record("example.com.", "mail.example.com.")]),
        ED25519_SIGNATURE_1,
    )
}

/// One signature check: what a validator spends a `Budget` verification on.
#[divan::bench(args = ["rsasha1-1024", "rsasha256-1024", "rsasha256-2048", "rsasha512-1024", "p256", "p384", "ed25519"])]
fn verify_signature(bencher: divan::Bencher<'_, '_>, which: &str) {
    let case = match which {
        "rsasha1-1024" => rsasha1_1024(),
        "rsasha256-1024" => rsasha256_1024(),
        "rsasha256-2048" => rsasha256_2048(),
        "rsasha512-1024" => rsasha512_1024(),
        "p256" => p256(),
        "p384" => p384(),
        _ => ed25519(),
    };
    bencher.bench_local(|| {
        verify(
            case.algorithm,
            black_box(&case.key),
            black_box(&case.signed),
            black_box(&case.signature),
        )
        .expect("an example verifies");
    });
}

/// A DS digest of the 1024-bit RSA key under each type.
#[divan::bench(args = [DigestType::SHA1, DigestType::SHA256, DigestType::SHA384])]
fn ds(bencher: divan::Bencher<'_, '_>, digest: DigestType) {
    let owner = dns("example.");
    let rdata = dnskey_rdata(256, 5, RFC4035_ZSK);
    bencher.bench_local(|| {
        ds_digest(digest, black_box(&owner), black_box(&rdata)).expect("supported")
    });
}

/// The NSEC3 hash of a name: `iterations + 1` SHA-1 rounds, at 0 (RFC 9276 §3.1), the RFC 5155 example's 12,
/// and 150, RFC 5155 §10.3's ceiling for 1024-bit keys.
#[divan::bench(args = [0, 12, 150])]
fn nsec3(bencher: divan::Bencher<'_, '_>, iterations: u16) {
    let owner = dns("www.example.com.");
    let salt = [0xaa, 0xbb, 0xcc, 0xdd];
    bencher.bench_local(|| {
        nsec3_hash(
            Nsec3HashAlgorithm::SHA1,
            black_box(&salt),
            black_box(iterations),
            black_box(&owner),
        )
        .expect("SHA-1")
    });
}

/// The NSEC3 hash at 150 iterations with a salt of 0, 64 and 255 octets: the `Budget` counts SHA-1 blocks, 1, 2
/// and 5 per iteration (D106), and the time should follow.
#[divan::bench(args = [0, 64, 255])]
fn nsec3_salt(bencher: divan::Bencher<'_, '_>, salt_len: usize) {
    let owner = dns("www.example.com.");
    let salt = vec![0xaa; salt_len];
    bencher.bench_local(|| {
        nsec3_hash(
            Nsec3HashAlgorithm::SHA1,
            black_box(&salt),
            black_box(150),
            black_box(&owner),
        )
        .expect("SHA-1")
    });
}

/// A captured signed `RRset`: the `RRset`, its RRSIG `RRset` and the DNSKEY `RRset` of the signer, all as the
/// zones served them.
fn captured(answer: &str, keys: &str) -> (RrSet<'static>, RrSet<'static>, RrSet<'static>) {
    let sets = |name: &str| RrSet::group(&response(name).answer);
    let mut answer = sets(answer).into_iter();
    let data = answer.next().expect("the answer");
    let sigs = answer.next().expect("its RRSIG");
    assert_eq!(sigs.rtype(), RecordType::RRSIG);
    let keys = sets(keys)
        .into_iter()
        .find(|set| set.rtype() == RecordType::DNSKEY)
        .expect("a DNSKEY RRset");
    (data, sigs, keys)
}

/// One whole `rrsig::verify` of a captured `RRset` per validated algorithm: canonical form, the signed data and
/// the signature, at the time of the capture. `la` signs its SOA under 7; the others sign an A or a SOA.
#[divan::bench(args = ["alg7", "alg8", "alg10", "alg13", "alg14", "alg15"])]
fn verify_rrset(bencher: divan::Bencher<'_, '_>, which: &str) {
    let (answer, keys) = match which {
        "alg7" => ("alg7_soa", "la_dnskey"),
        "alg8" => ("alg8_a", "nlnetlabs_nl_dnskey"),
        "alg10" => ("alg10_soa", "cat_dnskey"),
        "alg13" => ("alg13_a", "cloudflare_com_dnskey"),
        "alg14" => ("alg14_a", "fedoraproject_org_dnskey"),
        _ => ("alg15_a", "ed25519_nl_dnskey"),
    };
    let (data, sigs, keys) = captured(answer, keys);
    let now = captured_at();
    let sig = Signature::all(&sigs).into_iter().next().expect("an RRSIG");
    let key = Key::all(&keys)
        .into_iter()
        .find(|key| key.tag() == sig.rrsig().key_tag)
        .expect("the signer's key");
    bencher.bench_local(|| {
        rrsig::verify(
            black_box(&data),
            black_box(&sig),
            black_box(&key),
            now,
            &mut Budget::default(),
        )
        .expect("a capture verifies")
    });
}

/// Every capture, by the question it answers: what a caller hands the validator.
static CAPTURES: LazyLock<HashMap<(Name<'static>, RecordType), Message<'static>>> =
    LazyLock::new(|| {
        names()
            .iter()
            .map(|id| response(id))
            .filter_map(|message| {
                let question = message.questions.first()?;
                Some(((question.name.clone(), question.qtype), message))
            })
            .collect()
    });

/// The verdict on the captured answer `alg8_a` of `nlnetlabs.nl` at the time of the capture, with the captures
/// as the caller: five questions (the keys of `.`, `nl` and `nlnetlabs.nl` and their DS) when the validator
/// knows no zone.
fn validate(validator: &Validator, response: &Message<'static>) -> Verdict {
    let question = response.questions.first().expect("a question").clone();
    let mut validation = validator.start(&question, response, *CAPTURED_AT);
    loop {
        match validation.step() {
            Next::Ask(ask) => {
                validation.answer(CAPTURES.get(&(ask.name.clone().into_owned(), ask.qtype)));
            }
            Next::Done(verdict) => return verdict,
        }
    }
}

/// The time of the capture, read once: `captured_at` reads a file.
static CAPTURED_AT: LazyLock<u64> = LazyLock::new(|| u64::from(captured_at()));

/// The validator of the warm benches: the chain of `alg8_a` is in its cache.
static WARM: LazyLock<Validator> = LazyLock::new(|| {
    let validator = Validator::new(TrustAnchors::root(), Limits::default());
    let verdict = validate(&validator, &response("alg8_a"));
    assert!(matches!(verdict, Verdict::Secure { .. }), "{verdict:?}");
    validator
});

/// A whole validation of a captured secure answer under a validator that knows no zone: the keys of the chain
/// are verified (D86). Its threads share nothing: the scaling of the warm ones is read against this.
#[divan::bench(threads = [1, 2, 4, 8])]
fn validate_cold(bencher: divan::Bencher<'_, '_>) {
    let response = response("alg8_a");
    bencher.bench(|| {
        let validator = Validator::new(TrustAnchors::root(), Limits::default());
        validate(&validator, black_box(&response))
    });
}

/// The same under a validator whose key cache has the chain: no question, one signature check for the answer.
#[divan::bench(threads = [1, 2, 4, 8])]
fn validate_warm(bencher: divan::Bencher<'_, '_>) {
    let response = response("alg8_a");
    let validator = &*WARM;
    bencher.bench(|| validate(validator, black_box(&response)));
}

/// The captures as the upstream of a pipeline sends them.
static WIRES: LazyLock<HashMap<(Name<'static>, RecordType), Vec<u8>>> = LazyLock::new(|| {
    CAPTURES
        .iter()
        .map(|(question, message)| (question.clone(), message.to_vec().expect("a capture fits")))
        .collect()
});

/// A validating forward stage with no cache stage, under `allowance`, each client network's share being `share`.
fn validating_pipeline(validator: Validator, allowance: Allowance, share: Share) -> Pipeline {
    let clock = Arc::new(|| *CAPTURED_AT);
    let server = SocketAddr::from(([192, 0, 2, 53], 53));
    Pipeline::new(vec![Stage::Forward(
        Forward::new([server]).expect("a server").validating(
            Validating::new(validator, clock)
                .allowing(allowance)
                .sharing(Budgets::new(share).expect("a share in bounds")),
        ),
    )])
}

/// A client query for the question of `alg8_a`, with DO.
fn client_query() -> Vec<u8> {
    let question = response("alg8_a").questions[0].clone();
    let mut query = Message::query(7, question);
    query.edns = Some(Edns {
        flags: EdnsFlags::DO,
        ..Edns::default()
    });
    query.to_vec().expect("a query fits")
}

/// What `dedensd` does for one uncached query of a validating forward stage: the captures answer each question
/// the pipeline sends upstream, the client's and the validator's.
fn serve(pipeline: &Pipeline, query: &[u8], out: &mut [u8]) -> Step {
    let mut step = pipeline.query(query, Transport::Udp, Ipv4Addr::LOCALHOST.into(), 0, out);
    while let Step::Upstream(upstream) = step {
        let request = upstream.request();
        let question = request.questions.first().expect("a question");
        let wire = WIRES.get(&(question.name.clone().into_owned(), question.qtype));
        step = pipeline.receive(upstream, wire.map(Vec::as_slice), 0, out);
    }
    step
}

/// An allowance no bench spends.
const ENDLESS: Allowance = Allowance {
    per_second: u32::MAX,
    burst: u32::MAX,
    per_query: u32::MAX,
};

/// A share of one client network no bench spends.
const ENDLESS_SHARE: Share = Share {
    per_second: u32::MAX,
    burst: MAX_BUDGET,
    table: DEFAULT_SHARE.table,
};

/// The whole pipeline for a query whose zone keys are in no cache: the client's question, then the five of the
/// validator, the allowance admitting and charging it (D77). No cache stage: each run validates.
#[divan::bench(threads = [1, 2, 4, 8])]
fn serve_cold(bencher: divan::Bencher<'_, '_>) {
    let query = client_query();
    let mut out = vec![0; 1232];
    bencher
        .with_inputs(|| {
            validating_pipeline(
                Validator::new(TrustAnchors::root(), Limits::default()),
                ENDLESS,
                ENDLESS_SHARE,
            )
        })
        .bench_local_refs(|pipeline| {
            assert!(matches!(
                serve(pipeline, black_box(&query), &mut out),
                Step::Reply(_)
            ));
        });
}

/// The same with the chain in the validator's key cache: no question but the client's. The threads share one
/// allowance, as the clients of `dedensd` do: its lock is what the scaling shows.
#[divan::bench(threads = [1, 2, 4, 8])]
fn serve_warm(bencher: divan::Bencher<'_, '_>) {
    static PIPELINE: LazyLock<Pipeline> =
        LazyLock::new(|| validating_pipeline(WARM.clone(), ENDLESS, ENDLESS_SHARE));
    let query = client_query();
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        assert!(matches!(
            serve(&PIPELINE, black_box(&query), &mut out),
            Step::Reply(_)
        ));
    });
}

/// A query the spent allowance sheds (D77): SERVFAIL after the client's question, nothing validated.
#[divan::bench(threads = [1, 2, 4, 8])]
fn serve_shed(bencher: divan::Bencher<'_, '_>) {
    static PIPELINE: LazyLock<Pipeline> = LazyLock::new(|| {
        let spent = Allowance {
            burst: 0,
            ..Allowance::default()
        };
        validating_pipeline(WARM.clone(), spent, ENDLESS_SHARE)
    });
    let query = client_query();
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        assert!(matches!(
            serve(&PIPELINE, black_box(&query), &mut out),
            Step::Reply(_)
        ));
    });
}

/// A query of a client network that spent its share (D117), the allowance of all untouched: the same SERVFAIL, shed
/// by the share before the global allowance is asked.
#[divan::bench(threads = [1, 2, 4, 8])]
fn serve_shed_share(bencher: divan::Bencher<'_, '_>) {
    static PIPELINE: LazyLock<Pipeline> = LazyLock::new(|| {
        let spent = Share {
            burst: 0,
            ..DEFAULT_SHARE
        };
        validating_pipeline(WARM.clone(), ENDLESS, spent)
    });
    let query = client_query();
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        assert!(matches!(
            serve(&PIPELINE, black_box(&query), &mut out),
            Step::Reply(_)
        ));
    });
}
