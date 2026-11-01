//! DNSSEC crypto (D71): one signature verification per validated algorithm and key size, on the RFC examples the
//! tests verify (their keys and signatures are in `crates/dedens-dnssec/tests/common/mod.rs`), the DS digests
//! and the NSEC3 hash. The numbers size `Budget`'s defaults (`docs/benchmarks.md`).

use std::hint::black_box;

use dedens_dnssec::crypto::{Budget, ds_digest, nsec3_hash, verify};
use dedens_dnssec::rrsig::{self, Key, RrSet, Signature};
use dedens_proto::{DigestType, Nsec3HashAlgorithm, RecordType, SecAlgorithm};

#[path = "../../dedens-dnssec/tests/common/mod.rs"]
mod common;

use common::{
    ED25519_KEY_1, ED25519_SIGNATURE_1, P256_KEY, P256_SIGNATURE, P384_KEY, P384_SIGNATURE,
    RFC4034_NS1_SIGNATURE, RFC4034_ZSK, Rr, Rrsig, SHA512_KEY, SHA512_SIGNATURE,
    URI_DNSKEY_SIGNATURE, URI_KSK_1, URI_KSK_2, URI_MX_SIGNATURE, URI_ZSK, b64, canonical_name,
    dnskey_rdata, name, signed_data,
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
        RFC4034_ZSK,
        signed_data(&sig, &[a_record("ns1.example.")]),
        RFC4034_NS1_SIGNATURE,
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
    let owner = name("example.");
    let rdata = dnskey_rdata(256, 5, RFC4034_ZSK);
    bencher.bench_local(|| {
        ds_digest(digest, black_box(&owner), black_box(&rdata)).expect("supported")
    });
}

/// The NSEC3 hash of a name: `iterations + 1` SHA-1 rounds, at 0 (RFC 9276 §3.1), the RFC 5155 example's 12,
/// and 150, RFC 5155 §10.3's ceiling for 1024-bit keys.
#[divan::bench(args = [0, 12, 150])]
fn nsec3(bencher: divan::Bencher<'_, '_>, iterations: u16) {
    let owner = name("www.example.com.");
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

/// A captured signed `RRset`: the `RRset`, its RRSIG `RRset` and the DNSKEY `RRset` of the signer, all as the
/// zones served them.
fn captured(answer: &str, keys: &str) -> (RrSet<'static>, RrSet<'static>, RrSet<'static>) {
    let sets = |name: &str| RrSet::group(&common::capture(name).answer);
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
    let now = common::captured_at();
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
