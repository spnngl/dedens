//! DNSSEC crypto (D71): one signature verification per validated algorithm and key size, on the RFC examples the
//! tests verify (`crates/dedens-dnssec/tests/rfcNNNN.rs`; the strings below are copied from them), the DS digests
//! and the NSEC3 hash. The numbers size `Budget`'s defaults (`docs/benchmarks.md`).

use std::hint::black_box;

use dedens_dnssec::crypto::{ds_digest, nsec3_hash, verify};
use dedens_proto::{DigestType, Nsec3HashAlgorithm, SecAlgorithm};

#[path = "../../dedens-dnssec/tests/common/mod.rs"]
mod common;

use common::{Rr, Rrsig, b64, canonical_name, dnskey_rdata, name, signed_data};

fn main() {
    divan::main();
}

// RFC 4035 Appendix A (RSASHA1, 1024 bits).
const ZSK: &str = "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBV
    rZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e
    k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFo
    vBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI
    ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==";
const NS1_SIGNATURE: &str = "F1C9HVhIcs10cZU09G5yIVfKJy5yRQQ3qVet
    5pGhp82pzhAOMZ3K22JnmK4c+IjUeFp/to06
    im5FVpHtbFisdjyPq84bhTv8vrXt5AB1wNB+
    +iAqvIfdgW4sFNC6oADb1hK8QNauw9VePJhK
    v/iVXSYC0b7mPSU+EOlknFpVECs=";
// RFC 5702 §6.2 (RSASHA512, 1024 bits).
const SHA512_KEY: &str = "AwEAAdHoNTOW+et86KuJOWRD
    p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
    xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
    pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL";
const SHA512_SIGNATURE: &str = "tsb4wnjRUDnB1BUi+t
    6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
    eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
    DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
    =";
// RFC 8976 §A.4 (RSASHA256, 1024 and 2048 bits).
const URI_ZSK: &str = "AwEAAbMxuFuLeVDuOwIMzYOTD/bTREjLflo7wOi6ieIJhqltEzgjNzmWJf
    9kGwwDmzxU7kbthMEhBNBZNn84zmcyRSCMzuStWveL7xmqqUlE3swL8kLO
    vdZvc75XnmpHrk3ndTyEb6eZM7slh2C63Oh6K8VR5VkiZAkEGg0uZIT3Nj
    sF";
const URI_MX_SIGNATURE: &str = "kQAJQivmv6A5hqYBK8h6Z13ESY69gmosXwKI6WE09I8RFetfrxr24ecdnY
    d0lpnDtgNNSoHkYRSOoB+C4+zuJsoyAAzGo9uoWMWj97/2xeGhf3PTC9me
    Q9Ohi6hul9By7OR76XYmGhdWX8PBi60RUmZ1guslFBfQ8izwPqzuphs=";
const URI_KSK_1: &str = "AwEAAdkTaWkZtZuRh7/OobBUFxM+ytTst+bCu0r9w+rEwXD7GbDs0pIMhM
    enrZzoAvmv1fQxw2MGs6Ri6yPKfNULcFOSt9l8i6BVBLI+SKTY6XXeDUQp
    SEmSaxohHeRPMQFzpysfjxINp/L2rGtZ7yPmxY/XRiFPSO0myqwGJa9r06
    Zw9CHM5UDHKWV/E+zxPFq/I7CfPbrrzbUotBX7Z6Vh3Sarllbe8cGUB2UF
    NaTRgwB0TwDBPRD5ER3w2Dzbry9NhbElTr7vVfhaGWeOGuqAUXwlXEg6Cr
    NkmJXJ2F1Rzr9WHUzhp7uWxhAbmJREGfi2dEyPAbUAyCjBqhFaqglknvc=";
const URI_KSK_2: &str = "AwEAAenQaBoFmDmvRT+/H5oNbm0Tr5FmNRNDEun0Jpj/ELkzeUrTWhNpQm
    ZeIMC8I0kZ185tEvOnRvn8OvV39B17QIdrvvKGIh2HlgeDRCLolhaojfn2
    QM0DStjF/WWHpxJOmE6CIuvhqYEU37yoJscGAPpPVPzNvnL1HhYTaao1VR
    YWQ/maMrJ+bfHg+YX1N6M/8MnRjIKBif1FWjbCKvsn6dnuGGL9oCWYUFJ3
    DwofXuhgPyZMkzPc88YkJj5EMvbMH4wtelbCwC+ivx732l0w/rXJn0ciQS
    OgoeVvDio8dIJmWQITWQAuP+q/ZHFEFHPlrP3gvQh5mcVS48eLX71Bq7c=";
const URI_DNSKEY_SIGNATURE: &str = "DBE2gkKAoxJCfz47KKxzoImN/0AKArhIVHE7TyTwy0DdRPo44V5R+vL6th
    UxlQ1CJi2Rw0jwAXymx5Y3Q873pOEllH+4bJoIT4dmoBmPXfYWW7Clvw9U
    PKHRP0igKHmCVwIeBYDTU3gfLcMTbR4nEWPDN0GxlL1Mf7ITaC2Ioabo79
    Ip3M/MR8I3Vx/xZ4ZKKPHtLn3xUuJluPNanqJrED2gTslL2xWZ1tqjsAjJ
    v7JnJo2HJ8XVRB5zBto0IaJ2oBlqcjdcQ/0VlyoM8uOy1pDwHQ2BJl7322
    gNMHBP9HSiUPIOaIDNUCwW8eUcW6DIUk+s9u3GN1uTqwWzsYB/rA==";
// RFC 6605 §6 (ECDSAP256SHA256, ECDSAP384SHA384).
const P256_KEY: &str = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
    krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";
const P256_SIGNATURE: &str = "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
    yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==";
const P384_KEY: &str = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
    w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
    /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";
const P384_SIGNATURE: &str = "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
    95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
    WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm";
// RFC 8080 §6.1 (Ed25519).
const ED25519_KEY_1: &str = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";
const ED25519_SIGNATURE_1: &str = "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj
    H5GaMWeG96GUVZu6ECKOQmemHDg==";

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
        ZSK,
        signed_data(&sig, &[a_record("ns1.example.")]),
        NS1_SIGNATURE,
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
    let rdata = dnskey_rdata(256, 5, ZSK);
    bencher.bench_local(|| {
        ds_digest(digest, black_box(&owner), black_box(&rdata)).expect("supported")
    });
}

/// The NSEC3 hash of a name: `iterations + 1` SHA-1 rounds, at 0 (RFC 9276 §3.1), the RFC 5155 example's 12,
/// and the 150 of RFC 9276 §3.2's old ceiling.
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
