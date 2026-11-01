//! Helpers of the RFC tests: the examples' text decoded, and the data an RRSIG signs (RFC 4034 §3.1.8.1)
//! built by hand from it, so that no test relies on code under test.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses a subset of a shared module"
)]

use std::fs;
use std::path::PathBuf;

use data_encoding::{BASE64, HEXLOWER_PERMISSIVE};
use dedens_dnssec::crypto::Budget;
use dedens_dnssec::rrsig::{self, Key, RrSet, SigError, Signature, Verified};
use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{Message, Name, Record};

// spellchecker:off
/// RFC 4034 §5.4: the key of `dskey.example.com.` (algorithm 5, key tag 60485), the DNSKEY that RFC 4034 and
/// RFC 4509 give a DS for.
pub const DSKEY: &str = "AQOeiiR0GOMYkDshWoSKz9Xz
    fwJr1AYtsmx3TGkJaNXVbfi/
    2pHm822aJ5iI9BMzNXxeYCmZ
    DRD99WYwYqUSdjMmmAphXdvx
    egXd/M5+X7OrzKBaMbCVdFLU
    Uh6DhweJBjEVv5f2wwjM9Xzc
    nOf+EPbtG9DMBmADjFDc2w/r
    ljwvFw==";
// spellchecker:on

/// Base64 as the RFCs print it: split over lines and spaces.
pub fn b64(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    BASE64.decode(text.as_bytes()).expect("base64 in the RFC")
}

/// Hex as the RFCs print it, either case, split over lines and spaces.
pub fn hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    HEXLOWER_PERMISSIVE
        .decode(text.as_bytes())
        .expect("hex in the RFC")
}

pub fn name(text: &str) -> Name<'static> {
    text.parse().expect("a name")
}

/// A name in canonical wire form (RFC 4034 §6.2).
pub fn canonical_name(text: &str) -> Vec<u8> {
    let name = name(text);
    let mut buf = [0_u8; MAX_NAME_LEN];
    name.to_wire(&mut buf).to_ascii_lowercase()
}

/// The directory of the captured responses (`testdata/README.md`), from `dedens-dnssec` or `dedens-bench`.
pub fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dedens-dnssec/tests/testdata")
}

/// The ids of every captured file.
pub fn names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir())
        .expect("testdata directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "bin"))
        .map(|path| {
            path.file_stem()
                .expect("stem")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// Unix time of the capture run: the "now" the validation tests pass.
pub fn captured_at() -> u32 {
    fs::read_to_string(dir().join("captured_at"))
        .expect("captured_at")
        .trim()
        .parse()
        .expect("Unix time in seconds")
}

/// The captured response `name`, decoded without a violation.
pub fn capture(name: &str) -> Message<'static> {
    let wire = fs::read(dir().join(format!("{name}.bin"))).expect("captured file");
    let decoded = Message::decode(&wire).expect("decodes");
    assert_eq!(decoded.violations, [], "{name}");
    decoded.message.into_owned()
}

/// The records of one owner and type, class IN, as a decoder reads them from the answer of a message built by
/// hand with `rdatas` as given (names inside them in any case): none when the message does not decode cleanly.
pub fn try_records(
    owner: &str,
    rtype: u16,
    ttl: u32,
    rdatas: &[Vec<u8>],
) -> Option<Vec<Record<'static>>> {
    let mut wire = vec![0; 6];
    wire.extend(
        u16::try_from(rdatas.len())
            .expect("a few records")
            .to_be_bytes(),
    );
    wire.extend([0; 4]);
    for rdata in rdatas {
        wire.extend(name(owner).to_wire(&mut [0; MAX_NAME_LEN]));
        wire.extend(rtype.to_be_bytes());
        wire.extend(1_u16.to_be_bytes());
        wire.extend(ttl.to_be_bytes());
        wire.extend(
            u16::try_from(rdata.len())
                .expect("a short RDATA")
                .to_be_bytes(),
        );
        wire.extend(rdata);
    }
    let decoded = Message::decode(&wire).ok()?;
    decoded.violations.is_empty().then(|| {
        decoded
            .message
            .answer
            .into_iter()
            .map(Record::into_owned)
            .collect()
    })
}

/// [`try_records`] of RDATA that decodes.
pub fn records(owner: &str, rtype: u16, ttl: u32, rdatas: &[Vec<u8>]) -> Vec<Record<'static>> {
    try_records(owner, rtype, ttl, rdatas).expect("decodes without a violation")
}

/// Whether `sigs` sign `rrset` under `keys` at `now`, with the default budget.
pub fn check(
    rrset: &RrSet<'_>,
    sigs: &RrSet<'_>,
    keys: &RrSet<'_>,
    now: u32,
) -> Result<Verified, SigError> {
    rrsig::verify_any(
        rrset,
        &Signature::all(sigs),
        &Key::all(keys),
        now,
        &mut Budget::default(),
    )
}

/// An `RRset` of the records `rdatas` at `owner`, TTL 3600.
pub fn rrset(owner: &str, rtype: u16, rdatas: &[Vec<u8>]) -> RrSet<'static> {
    RrSet::group(&records(owner, rtype, 3600, rdatas))
        .pop()
        .expect("one RRset")
}

/// The RRSIG record of `rrsig` over `owner`'s `RRset`, with its signature in base64, as an `RRset` (TTL 3600).
pub fn rrsig_set(owner: &str, rrsig: &Rrsig<'_>, signature: &str) -> RrSet<'static> {
    let mut rdata = rrsig.type_covered.to_be_bytes().to_vec();
    rdata.extend([rrsig.algorithm, rrsig.labels]);
    rdata.extend(rrsig.original_ttl.to_be_bytes());
    rdata.extend(rrsig.expiration.to_be_bytes());
    rdata.extend(rrsig.inception.to_be_bytes());
    rdata.extend(rrsig.key_tag.to_be_bytes());
    rdata.extend(canonical_name(rrsig.signer));
    rdata.extend(b64(signature));
    rrset(owner, 46, &[rdata])
}

/// DNSKEY RDATA (RFC 4034 §2.1): flags, protocol 3, the algorithm and the public key.
pub fn dnskey_rdata(flags: u16, algorithm: u8, key_base64: &str) -> Vec<u8> {
    let mut rdata = flags.to_be_bytes().to_vec();
    rdata.extend([3, algorithm]);
    rdata.extend(b64(key_base64));
    rdata
}

/// The fields of RRSIG RDATA before the signature (RFC 4034 §3.1).
pub struct Rrsig<'a> {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: &'a str,
}

/// One record of an `RRset`: owner, TTL and RDATA (class IN; names inside RDATA already lowercase).
pub struct Rr<'a> {
    pub owner: &'a str,
    pub rdata: Vec<u8>,
}

/// The data a signature covers: the RRSIG RDATA without the signature, then the `RRset` in canonical form and
/// order (RFC 4034 §3.1.8.1, §6.3), each record with the RRSIG's original TTL (§6.2).
pub fn signed_data(rrsig: &Rrsig<'_>, rrset: &[Rr<'_>]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(rrsig.type_covered.to_be_bytes());
    data.extend([rrsig.algorithm, rrsig.labels]);
    data.extend(rrsig.original_ttl.to_be_bytes());
    data.extend(rrsig.expiration.to_be_bytes());
    data.extend(rrsig.inception.to_be_bytes());
    data.extend(rrsig.key_tag.to_be_bytes());
    data.extend(canonical_name(rrsig.signer));

    let mut records: Vec<&Rr<'_>> = rrset.iter().collect();
    records.sort_by(|a, b| a.rdata.cmp(&b.rdata));
    for record in records {
        data.extend(canonical_name(record.owner));
        data.extend(rrsig.type_covered.to_be_bytes());
        data.extend(1_u16.to_be_bytes());
        data.extend(rrsig.original_ttl.to_be_bytes());
        data.extend(
            u16::try_from(record.rdata.len())
                .expect("a short RDATA")
                .to_be_bytes(),
        );
        data.extend(&record.rdata);
    }
    data
}

// spellchecker:off
// RFC 4035 Appendix A: the zone signing key (tag 38519) and key signing key (tag 9465) of `example.`.
pub const RFC4034_ZSK: &str = "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBV
    rZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e
    k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFo
    vBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI
    ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==";

// ns1.example. 3600 IN A 192.0.2.1, signed by the RFC4034_ZSK.
pub const RFC4034_NS1_SIGNATURE: &str = "F1C9HVhIcs10cZU09G5yIVfKJy5yRQQ3qVet
    5pGhp82pzhAOMZ3K22JnmK4c+IjUeFp/to06
    im5FVpHtbFisdjyPq84bhTv8vrXt5AB1wNB+
    +iAqvIfdgW4sFNC6oADb1hK8QNauw9VePJhK
    v/iVXSYC0b7mPSU+EOlknFpVECs=";

// RFC 5702 §6.2: 1024 bits.
pub const SHA512_KEY: &str = "AwEAAdHoNTOW+et86KuJOWRD
    p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
    xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
    pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL";

pub const SHA512_SIGNATURE: &str = "tsb4wnjRUDnB1BUi+t
    6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
    eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
    DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
    =";

// RFC 8976 §A.4, uri.arpa. zone: the ZSK (1024 bits) and its signature over the MX `RRset`.
pub const URI_ZSK: &str = "AwEAAbMxuFuLeVDuOwIMzYOTD/bTREjLflo7wOi6ieIJhqltEzgjNzmWJf
    9kGwwDmzxU7kbthMEhBNBZNn84zmcyRSCMzuStWveL7xmqqUlE3swL8kLO
    vdZvc75XnmpHrk3ndTyEb6eZM7slh2C63Oh6K8VR5VkiZAkEGg0uZIT3Nj
    sF";

pub const URI_MX_SIGNATURE: &str = "kQAJQivmv6A5hqYBK8h6Z13ESY69gmosXwKI6WE09I8RFetfrxr24ecdnY
    d0lpnDtgNNSoHkYRSOoB+C4+zuJsoyAAzGo9uoWMWj97/2xeGhf3PTC9me
    Q9Ohi6hul9By7OR76XYmGhdWX8PBi60RUmZ1guslFBfQ8izwPqzuphs=";

// The two KSKs (2048 bits) and the signature of key 12670 over the DNSKEY `RRset`.
pub const URI_KSK_1: &str = "AwEAAdkTaWkZtZuRh7/OobBUFxM+ytTst+bCu0r9w+rEwXD7GbDs0pIMhM
    enrZzoAvmv1fQxw2MGs6Ri6yPKfNULcFOSt9l8i6BVBLI+SKTY6XXeDUQp
    SEmSaxohHeRPMQFzpysfjxINp/L2rGtZ7yPmxY/XRiFPSO0myqwGJa9r06
    Zw9CHM5UDHKWV/E+zxPFq/I7CfPbrrzbUotBX7Z6Vh3Sarllbe8cGUB2UF
    NaTRgwB0TwDBPRD5ER3w2Dzbry9NhbElTr7vVfhaGWeOGuqAUXwlXEg6Cr
    NkmJXJ2F1Rzr9WHUzhp7uWxhAbmJREGfi2dEyPAbUAyCjBqhFaqglknvc=";

pub const URI_KSK_2: &str = "AwEAAenQaBoFmDmvRT+/H5oNbm0Tr5FmNRNDEun0Jpj/ELkzeUrTWhNpQm
    ZeIMC8I0kZ185tEvOnRvn8OvV39B17QIdrvvKGIh2HlgeDRCLolhaojfn2
    QM0DStjF/WWHpxJOmE6CIuvhqYEU37yoJscGAPpPVPzNvnL1HhYTaao1VR
    YWQ/maMrJ+bfHg+YX1N6M/8MnRjIKBif1FWjbCKvsn6dnuGGL9oCWYUFJ3
    DwofXuhgPyZMkzPc88YkJj5EMvbMH4wtelbCwC+ivx732l0w/rXJn0ciQS
    OgoeVvDio8dIJmWQITWQAuP+q/ZHFEFHPlrP3gvQh5mcVS48eLX71Bq7c=";

pub const URI_DNSKEY_SIGNATURE: &str = "DBE2gkKAoxJCfz47KKxzoImN/0AKArhIVHE7TyTwy0DdRPo44V5R+vL6th
    UxlQ1CJi2Rw0jwAXymx5Y3Q873pOEllH+4bJoIT4dmoBmPXfYWW7Clvw9U
    PKHRP0igKHmCVwIeBYDTU3gfLcMTbR4nEWPDN0GxlL1Mf7ITaC2Ioabo79
    Ip3M/MR8I3Vx/xZ4ZKKPHtLn3xUuJluPNanqJrED2gTslL2xWZ1tqjsAjJ
    v7JnJo2HJ8XVRB5zBto0IaJ2oBlqcjdcQ/0VlyoM8uOy1pDwHQ2BJl7322
    gNMHBP9HSiUPIOaIDNUCwW8eUcW6DIUk+s9u3GN1uTqwWzsYB/rA==";

pub const P256_KEY: &str = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
    krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";

pub const P256_SIGNATURE: &str = "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
    yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==";

pub const P384_KEY: &str = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
    w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
    /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";

pub const P384_SIGNATURE: &str = "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
    95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
    WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm";

pub const ED25519_KEY_1: &str = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";

pub const ED25519_SIGNATURE_1: &str = "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj
    H5GaMWeG96GUVZu6ECKOQmemHDg==";
// spellchecker:on
