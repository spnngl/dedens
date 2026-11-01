//! RFC 5155 §5 (the NSEC3 hash) against the hashes of Appendix A and B, §2 (algorithm 7 is RSASHA1's alias, with
//! the 512-bit key of Appendix A that D71 refuses), and the denials of §8 against the responses of Appendix B.

mod common;
#[path = "common/denial.rs"]
mod support;

use common::{Rr, Rrsig, b64, canonical_name, dnskey_rdata, name, signed_data};
use data_encoding::BASE32HEX_NOPAD;
use dedens_dnssec::crypto::{UnsupportedNsec3Hash, VerifyError, key_tag, nsec3_hash, verify};
use dedens_dnssec::denial::{Fact, Proof, Unproven};
use dedens_proto::{Nsec3HashAlgorithm, Record, RecordType, SecAlgorithm, Ttl};
use support::{nsec3_with, pick, prove, prove_wildcard, zone};

const SALT: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
const ITERATIONS: u16 = 12;

/// Appendix A, "The zone is preceded by a list that contains the hashes of the original ownernames", then
/// the hashes Appendix B prints.
const HASHES: [(&str, &str); 16] = [
    ("example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
    ("a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
    ("ai.example.", "gjeqe526plbf1g8mklp59enfd789njgi"),
    ("ns1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
    ("ns2.example.", "q04jkcevqvmu85r014c7dkba38o0ji5r"),
    ("w.example.", "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
    ("*.w.example.", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
    ("x.w.example.", "b4um86eghhds6nea196smvmlo4ors995"),
    ("y.w.example.", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
    ("x.y.w.example.", "2vptu5timamqttgl4luu9kg21e0aor3s"),
    ("xx.example.", "t644ebqk9bibcna874givr6joj62mlhv"),
    (
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.",
        "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
    ),
    ("c.x.w.example.", "0va5bpr2ou0vk0lbqeeljri88laipsfh"),
    ("*.x.w.example.", "92pqneegtaue7pjatc3l3qnk738c6v5m"),
    ("c.example.", "4g6p9u5gvfshp30pqecj98b3maqbn1ck"),
    ("z.w.example.", "qlu7gtfaeh0ek0c05ksfhdpbcgglbe03"),
];

// Appendix A: the zone's 512-bit ZSK, key tag 40430, and its RRSIG over the SOA `RRset`.
const ZSK: &str = "AwEAAaetidLzsKWUt4swWR8yu0wPHPiUi8LU
    sAD0QPWU+wzt89epO6tHzkMBVDkC7qphQO2h
    TY4hHn9npWFRw5BYubE=";

fn hashed(owner: &str, iterations: u16) -> String {
    let hash =
        nsec3_hash(Nsec3HashAlgorithm::SHA1, &SALT, iterations, &name(owner)).expect("SHA-1");
    BASE32HEX_NOPAD.encode(&hash).to_ascii_lowercase()
}

#[test]
fn hashes_are_the_rfcs() {
    for (owner, hash) in HASHES {
        assert_eq!(hashed(owner, ITERATIONS), hash, "{owner}");
    }
}

#[test]
fn the_owner_is_hashed_in_lower_case() {
    // §5: the owner is in canonical form (RFC 4034 §6.2).
    assert_eq!(
        hashed("A.EXAMPLE.", ITERATIONS),
        "35mthgpgcu1qg68fab165klnsnk3dpvl"
    );
    assert_eq!(
        hashed("X.W.Example.", ITERATIONS),
        "b4um86eghhds6nea196smvmlo4ors995"
    );
}

#[test]
fn the_count_and_the_salt_change_the_hash() {
    // The vectors pin 12 iterations and the salt; other values must not give the same hash.
    let owner = name("example.");
    let twelve = nsec3_hash(Nsec3HashAlgorithm::SHA1, &SALT, 12, &owner).expect("SHA-1");
    let zero = nsec3_hash(Nsec3HashAlgorithm::SHA1, &SALT, 0, &owner).expect("SHA-1");
    let empty_salt = nsec3_hash(Nsec3HashAlgorithm::SHA1, &[], 12, &owner).expect("SHA-1");
    assert_ne!(twelve, zero);
    assert_ne!(twelve, empty_salt);
    assert_eq!(
        BASE32HEX_NOPAD.encode(&twelve).to_ascii_lowercase(),
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
    );
}

#[test]
fn the_maximum_count_is_computed() {
    // RFC 9276 §3.2 is the caller's policy: the hash still takes 65536 rounds and ends.
    let _ =
        nsec3_hash(Nsec3HashAlgorithm::SHA1, &SALT, u16::MAX, &name("example.")).expect("SHA-1");
}

#[test]
fn algorithms_other_than_sha1_are_unsupported() {
    for code in 0..=u8::MAX {
        if code == 1 {
            continue;
        }
        let algorithm = Nsec3HashAlgorithm(code);
        assert_eq!(
            nsec3_hash(algorithm, &SALT, ITERATIONS, &name("example.")),
            Err(UnsupportedNsec3Hash(algorithm))
        );
    }
}

#[test]
fn the_512_bit_zone_key_of_appendix_a_is_unusable() {
    // §2: algorithm 7 is RSASHA1 for NSEC3 zones; RFC 3110 allows 512 bits, D71 starts at 1024.
    let rdata = dnskey_rdata(256, 7, ZSK);
    assert_eq!(key_tag(&rdata), 40430);
    let rrsig = Rrsig {
        type_covered: 6,
        algorithm: 7,
        labels: 1,
        original_ttl: 3600,
        expiration: 1_429_574_399,
        inception: 1_129_852_800,
        key_tag: 40430,
        signer: "example.",
    };
    // `example. 3600 IN SOA ns1.example. bugs.x.w.example. 1 3600 300 3600000 3600`.
    let mut soa = canonical_name("ns1.example.");
    soa.extend(canonical_name("bugs.x.w.example."));
    for field in [1_u32, 3600, 300, 3_600_000, 3600] {
        soa.extend(field.to_be_bytes());
    }
    let signed = signed_data(
        &rrsig,
        &[Rr {
            owner: "example.",
            rdata: soa,
        }],
    );
    let signature = b64("Hu25UIyNPmvPIVBrldN+9Mlp9Zql39qaUd8i
         q4ZLlYWfUUbbAS41pG+68z81q1xhkYAcEyHd
         VI2LmKusbZsT0Q==");
    assert_eq!(
        verify(
            SecAlgorithm::RSASHA1_NSEC3_SHA1,
            &b64(ZSK),
            &signed,
            &signature
        ),
        Err(VerifyError::UnusableKey)
    );
}

// The denials of §8 and Appendix B, from the NSEC3 records of Appendix A, `../dedens-proto/tests/zones`.

const APEX: &str = "example.";
/// The TTL of every record of Appendix A.
const TTL: Ttl = Ttl::from_wire(3600);
const NAME_ERROR: Fact = Fact::NameError { compact: false };

// The hashes of Appendix A, by the name they are of.
const EXAMPLE: &str = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom";
const NS1: &str = "2t7b4g4vsa5smi47k61mv5bv1a22bojr";
const A: &str = "35mthgpgcu1qg68fab165klnsnk3dpvl";
const X_W: &str = "b4um86eghhds6nea196smvmlo4ors995";
const Y_W: &str = "ji6neoaepv8b5o6k4ev33abha8ht9fgc";
const W: &str = "k8udemvp1j2f7eg6jebps17vp3n8i58h";
const NS2: &str = "q04jkcevqvmu85r014c7dkba38o0ji5r";
const WILDCARD_W: &str = "r53bq7cc2uvmubfu5ocmm6pers9tk9en";

fn nsec3s(hashes: &[&str]) -> Vec<Record<'static>> {
    let owners: Vec<String> = hashes.iter().map(|h| format!("{h}.example.")).collect();
    let owners: Vec<&str> = owners.iter().map(String::as_str).collect();
    pick(
        &zone("../dedens-proto/tests/zones/rfc5155_appendix_a.zone"),
        RecordType::NSEC3,
        &owners,
    )
}

fn proof(fact: Fact) -> Proof {
    Proof { fact, ttl: TTL }
}

/// B.1: `x.w.example.` is the closest encloser of `a.c.x.w.example.`, `c.x.w.example.` is covered by the apex's
/// record and `*.x.w.example.` by `a.example.`'s.
#[test]
fn b1_name_error() {
    let records = nsec3s(&[EXAMPLE, X_W, A]);
    assert_eq!(
        prove(APEX, "a.c.x.w.example.", RecordType::A, &records),
        Ok(proof(NAME_ERROR))
    );
    // Each of the three is needed.
    assert_eq!(
        prove(
            APEX,
            "a.c.x.w.example.",
            RecordType::A,
            &nsec3s(&[EXAMPLE, X_W])
        ),
        Err(Unproven::WildcardNotDenied)
    );
    assert_eq!(
        prove(APEX, "a.c.x.w.example.", RecordType::A, &nsec3s(&[X_W, A])),
        Err(Unproven::NoClosestEncloser)
    );
    assert_eq!(
        prove(
            APEX,
            "a.c.x.w.example.",
            RecordType::A,
            &nsec3s(&[EXAMPLE, A])
        ),
        Err(Unproven::NoClosestEncloser)
    );
}

/// B.2: `ns1.example.` exists and has no MX; B.2.1: `y.w.example.` is an empty non-terminal, no data as well.
#[test]
fn b2_no_data() {
    assert_eq!(
        prove(APEX, "ns1.example.", RecordType::MX, &nsec3s(&[NS1])),
        Ok(proof(Fact::NoData))
    );
    assert_eq!(
        prove(APEX, "ns1.example.", RecordType::A, &nsec3s(&[NS1])),
        Err(Unproven::TypePresent)
    );
    assert_eq!(
        prove(APEX, "y.w.example.", RecordType::A, &nsec3s(&[Y_W])),
        Ok(proof(Fact::NoData))
    );
}

/// B.3: the referral to `c.example.` is to an unsigned zone: the closest provable encloser of `c.example.` is
/// `example.`, and the record that covers `c.example.` has the opt-out flag.
#[test]
fn b3_referral_to_opt_out_zone() {
    let records = nsec3s(&[A, EXAMPLE]);
    assert_eq!(
        prove(APEX, "c.example.", RecordType::DS, &records),
        Ok(proof(Fact::InsecureDelegation))
    );
    // Without the flag nothing says `c.example.` has no signed zone.
    let records: Vec<_> = records
        .iter()
        .map(|r| nsec3_with(r, Nsec3HashAlgorithm::SHA1, 0, ITERATIONS))
        .collect();
    assert_eq!(
        prove(APEX, "c.example.", RecordType::DS, &records),
        Err(Unproven::WildcardNotDenied)
    );
}

/// B.4: the RRSIG of `a.z.w.example.` has 2 labels, and `z.w.example.` is covered by `ns2`'s record.
#[test]
fn b4_wildcard_expansion() {
    assert_eq!(
        prove_wildcard(APEX, "a.z.w.example.", 2, &nsec3s(&[NS2])),
        Ok(proof(Fact::WildcardAnswer))
    );
    // `w.example.` exists: with 3 labels the next closer name is `a.z.w.example.`, covered by nothing here.
    assert_eq!(
        prove_wildcard(APEX, "a.z.w.example.", 3, &nsec3s(&[NS2])),
        Err(Unproven::NotCovered)
    );
    // `x.w.example.` exists.
    assert_eq!(
        prove_wildcard(APEX, "a.x.w.example.", 2, &nsec3s(&[X_W])),
        Err(Unproven::CloserNameExists)
    );
}

/// B.5: `w.example.` is the closest encloser, `*.w.example.` exists with MX only.
#[test]
fn b5_wildcard_no_data() {
    let records = nsec3s(&[W, NS2, WILDCARD_W]);
    assert_eq!(
        prove(APEX, "a.z.w.example.", RecordType::AAAA, &records),
        Ok(proof(Fact::WildcardNoData))
    );
    assert_eq!(
        prove(APEX, "a.z.w.example.", RecordType::MX, &records),
        Err(Unproven::WildcardHasType)
    );
}

/// B.6: the record of `example.` has SOA, so it comes from the child zone, not the delegation.
#[test]
fn b6_ds_from_the_child() {
    assert_eq!(
        prove(APEX, "example.", RecordType::DS, &nsec3s(&[EXAMPLE])),
        Err(Unproven::FromChildApex)
    );
}

/// §8.1, §8.2: records of an unknown hash algorithm or with flags other than 0 and 1 are ignored, and so are
/// those of other parameters than the first's.
#[test]
fn unusable_records_are_ignored() {
    let records = nsec3s(&[EXAMPLE, X_W, A]);
    let unknown: Vec<_> = records
        .iter()
        .map(|r| nsec3_with(r, Nsec3HashAlgorithm(2), 1, ITERATIONS))
        .collect();
    assert_eq!(
        prove(APEX, "a.c.x.w.example.", RecordType::A, &unknown),
        Err(Unproven::NoUsableRecords)
    );
    let flags: Vec<_> = records
        .iter()
        .map(|r| nsec3_with(r, Nsec3HashAlgorithm::SHA1, 2, ITERATIONS))
        .collect();
    assert_eq!(
        prove(APEX, "a.c.x.w.example.", RecordType::A, &flags),
        Err(Unproven::NoUsableRecords)
    );
    // A record of another chain that the proof does not use.
    let mut mixed = records.clone();
    mixed.push(nsec3_with(
        &records[0],
        Nsec3HashAlgorithm(2),
        1,
        ITERATIONS,
    ));
    assert_eq!(
        prove(APEX, "a.c.x.w.example.", RecordType::A, &mixed),
        Ok(proof(NAME_ERROR))
    );
}

/// §8.3, RFC 6840 §4.1: `a.example.` has NS and no SOA, so no name below it is in the zone: it is no closest
/// encloser, though its record matches an ancestor and covers `x.a.example.`.
#[test]
fn closest_encloser_is_not_a_delegation() {
    assert_eq!(
        prove(APEX, "x.a.example.", RecordType::A, &nsec3s(&[A])),
        Err(Unproven::EncloserBelowCut)
    );
}
