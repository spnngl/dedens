//! The DNSSEC captures of `testdata/dnssec/` and the RFC examples' keys and signatures, with the data an RRSIG
//! signs (RFC 4034 §3.1.8.1) built by hand from them, so that no test relies on the code under test.

use std::collections::HashMap;
use std::fs;

use data_encoding::BASE64;
use dedens_proto::{MAX_NAME_LEN, Message, Name, RecordType};

use crate::{dns, message, path};

/// The ids of every capture (`<id>.bin`), sorted.
///
/// # Panics
///
/// When the directory cannot be read.
#[must_use]
pub fn names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(path("dnssec"))
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

/// The Unix time of the capture run: the "now" at which the signatures are valid.
///
/// # Panics
///
/// When `captured_at` cannot be read.
#[must_use]
pub fn captured_at() -> u32 {
    fs::read_to_string(path("dnssec/captured_at"))
        .expect("captured_at")
        .trim()
        .parse()
        .expect("Unix time in seconds")
}

/// The capture `id`, as `testdata/dnssec/README.md` names it.
///
/// # Panics
///
/// When the file cannot be read.
#[must_use]
pub fn capture(id: &str) -> Vec<u8> {
    fs::read(path(&format!("dnssec/{id}.bin"))).expect("a capture")
}

/// The capture `id`, decoded without a violation.
///
/// # Panics
///
/// When the file cannot be read, does not decode or breaks a rule.
#[must_use]
#[track_caller]
pub fn response(id: &str) -> Message<'static> {
    message(&capture(id))
}

/// The captures by question, an upstream that answers each question asked of it with its capture.
pub struct Captures(HashMap<(Name<'static>, RecordType), Vec<u8>>);

impl Captures {
    /// Every capture.
    ///
    /// # Panics
    ///
    /// When a capture cannot be read or decoded, or two answer one question.
    #[must_use]
    pub fn new() -> Self {
        let mut all = Self(HashMap::new());
        for id in names() {
            let wire = capture(&id);
            let key = Self::question(&wire);
            assert!(
                all.0.insert(key, wire).is_none(),
                "{id}: one capture a question"
            );
        }
        all
    }

    /// The same captures, `wire` answering its question instead of the one captured.
    ///
    /// # Panics
    ///
    /// When `wire` does not decode to a message with a question.
    #[must_use]
    pub fn with(mut self, wire: Vec<u8>) -> Self {
        self.0.insert(Self::question(&wire), wire);
        self
    }

    /// The same captures without the answer to `name` and `qtype`: upstream stays silent.
    #[must_use]
    pub fn without(mut self, name: &str, qtype: RecordType) -> Self {
        self.0.remove(&(dns(name), qtype));
        self
    }

    /// The capture answering the first question of `request`.
    #[must_use]
    pub fn answer(&self, request: &Message<'_>) -> Option<&[u8]> {
        let question = request.questions.first()?;
        self.0
            .get(&(question.name.clone().into_owned(), question.qtype))
            .map(Vec::as_slice)
    }

    fn question(wire: &[u8]) -> (Name<'static>, RecordType) {
        let question = message(wire)
            .questions
            .into_iter()
            .next()
            .expect("a question");
        (question.name, question.qtype)
    }
}

impl Default for Captures {
    fn default() -> Self {
        Self::new()
    }
}

/// Base64 as the RFCs print it: split over lines and spaces.
///
/// # Panics
///
/// When `text` is not base64.
#[must_use]
pub fn b64(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    BASE64.decode(text.as_bytes()).expect("base64 in the RFC")
}

/// A name in presentation format, in canonical wire form (RFC 4034 §6.2).
///
/// # Panics
///
/// When `text` is not a name.
#[must_use]
pub fn canonical_name(text: &str) -> Vec<u8> {
    let name: Name<'_> = text.parse().expect("a name");
    let mut buf = [0_u8; MAX_NAME_LEN];
    name.to_wire(&mut buf).to_ascii_lowercase()
}

/// DNSKEY RDATA (RFC 4034 §2.1): flags, protocol 3, the algorithm and the public key.
///
/// # Panics
///
/// When `key_base64` is not base64.
#[must_use]
pub fn dnskey_rdata(flags: u16, algorithm: u8, key_base64: &str) -> Vec<u8> {
    let mut rdata = flags.to_be_bytes().to_vec();
    rdata.extend([3, algorithm]);
    rdata.extend(b64(key_base64));
    rdata
}

/// The fields of RRSIG RDATA before the signature (RFC 4034 §3.1).
pub struct Rrsig<'a> {
    /// The type of the `RRset` signed.
    pub type_covered: u16,
    /// The algorithm number.
    pub algorithm: u8,
    /// The labels of the owner name, the root and a wildcard's `*` not counted.
    pub labels: u8,
    /// The `RRset`'s TTL in its zone.
    pub original_ttl: u32,
    /// The end of the validity period, Unix time.
    pub expiration: u32,
    /// The start of the validity period, Unix time.
    pub inception: u32,
    /// The key tag of the signing key.
    pub key_tag: u16,
    /// The zone of the signing key, in presentation format.
    pub signer: &'a str,
}

/// One record of an `RRset`: owner and RDATA (class IN; names inside RDATA already lowercase).
pub struct Rr<'a> {
    /// The owner name, in presentation format.
    pub owner: &'a str,
    /// The RDATA.
    pub rdata: Vec<u8>,
}

/// The data a signature covers: the RRSIG RDATA without the signature, then the `RRset` in canonical form and
/// order (RFC 4034 §3.1.8.1, §6.3), each record with the RRSIG's original TTL (§6.2).
///
/// # Panics
///
/// When a name is not one, or an RDATA is longer than 65 535 bytes.
#[must_use]
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
/// RFC 4035 Appendix A: the zone signing key (tag 38519) of `example.`, which also has a key signing key (tag
/// 9465).
pub const RFC4035_ZSK: &str = "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBV
    rZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e
    k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFo
    vBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI
    ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==";

/// RFC 4035 Appendix A: the signature of `ns1.example. 3600 IN A 192.0.2.1` by [`RFC4035_ZSK`].
pub const RFC4035_NS1_SIGNATURE: &str = "F1C9HVhIcs10cZU09G5yIVfKJy5yRQQ3qVet
    5pGhp82pzhAOMZ3K22JnmK4c+IjUeFp/to06
    im5FVpHtbFisdjyPq84bhTv8vrXt5AB1wNB+
    +iAqvIfdgW4sFNC6oADb1hK8QNauw9VePJhK
    v/iVXSYC0b7mPSU+EOlknFpVECs=";

/// RFC 5702 §6.2: an RSA key of 1024 bits.
pub const SHA512_KEY: &str = "AwEAAdHoNTOW+et86KuJOWRD
    p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
    xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
    pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL";

/// RFC 5702 §6.2: the RSA/SHA-512 signature by [`SHA512_KEY`].
pub const SHA512_SIGNATURE: &str = "tsb4wnjRUDnB1BUi+t
    6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
    eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
    DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
    =";

/// RFC 8976 §A.4, the `uri.arpa.` zone: its zone signing key (1024 bits).
pub const URI_ZSK: &str = "AwEAAbMxuFuLeVDuOwIMzYOTD/bTREjLflo7wOi6ieIJhqltEzgjNzmWJf
    9kGwwDmzxU7kbthMEhBNBZNn84zmcyRSCMzuStWveL7xmqqUlE3swL8kLO
    vdZvc75XnmpHrk3ndTyEb6eZM7slh2C63Oh6K8VR5VkiZAkEGg0uZIT3Nj
    sF";

/// RFC 8976 §A.4: the signature of [`URI_ZSK`] over the MX `RRset`.
pub const URI_MX_SIGNATURE: &str = "kQAJQivmv6A5hqYBK8h6Z13ESY69gmosXwKI6WE09I8RFetfrxr24ecdnY
    d0lpnDtgNNSoHkYRSOoB+C4+zuJsoyAAzGo9uoWMWj97/2xeGhf3PTC9me
    Q9Ohi6hul9By7OR76XYmGhdWX8PBi60RUmZ1guslFBfQ8izwPqzuphs=";

/// RFC 8976 §A.4: the first of the two key signing keys (2048 bits).
pub const URI_KSK_1: &str = "AwEAAdkTaWkZtZuRh7/OobBUFxM+ytTst+bCu0r9w+rEwXD7GbDs0pIMhM
    enrZzoAvmv1fQxw2MGs6Ri6yPKfNULcFOSt9l8i6BVBLI+SKTY6XXeDUQp
    SEmSaxohHeRPMQFzpysfjxINp/L2rGtZ7yPmxY/XRiFPSO0myqwGJa9r06
    Zw9CHM5UDHKWV/E+zxPFq/I7CfPbrrzbUotBX7Z6Vh3Sarllbe8cGUB2UF
    NaTRgwB0TwDBPRD5ER3w2Dzbry9NhbElTr7vVfhaGWeOGuqAUXwlXEg6Cr
    NkmJXJ2F1Rzr9WHUzhp7uWxhAbmJREGfi2dEyPAbUAyCjBqhFaqglknvc=";

/// RFC 8976 §A.4: the second key signing key (2048 bits).
pub const URI_KSK_2: &str = "AwEAAenQaBoFmDmvRT+/H5oNbm0Tr5FmNRNDEun0Jpj/ELkzeUrTWhNpQm
    ZeIMC8I0kZ185tEvOnRvn8OvV39B17QIdrvvKGIh2HlgeDRCLolhaojfn2
    QM0DStjF/WWHpxJOmE6CIuvhqYEU37yoJscGAPpPVPzNvnL1HhYTaao1VR
    YWQ/maMrJ+bfHg+YX1N6M/8MnRjIKBif1FWjbCKvsn6dnuGGL9oCWYUFJ3
    DwofXuhgPyZMkzPc88YkJj5EMvbMH4wtelbCwC+ivx732l0w/rXJn0ciQS
    OgoeVvDio8dIJmWQITWQAuP+q/ZHFEFHPlrP3gvQh5mcVS48eLX71Bq7c=";

/// RFC 8976 §A.4: the signature of key 12670 over the DNSKEY `RRset`.
pub const URI_DNSKEY_SIGNATURE: &str = "DBE2gkKAoxJCfz47KKxzoImN/0AKArhIVHE7TyTwy0DdRPo44V5R+vL6th
    UxlQ1CJi2Rw0jwAXymx5Y3Q873pOEllH+4bJoIT4dmoBmPXfYWW7Clvw9U
    PKHRP0igKHmCVwIeBYDTU3gfLcMTbR4nEWPDN0GxlL1Mf7ITaC2Ioabo79
    Ip3M/MR8I3Vx/xZ4ZKKPHtLn3xUuJluPNanqJrED2gTslL2xWZ1tqjsAjJ
    v7JnJo2HJ8XVRB5zBto0IaJ2oBlqcjdcQ/0VlyoM8uOy1pDwHQ2BJl7322
    gNMHBP9HSiUPIOaIDNUCwW8eUcW6DIUk+s9u3GN1uTqwWzsYB/rA==";

/// RFC 6605 §6.1: the P-256 key.
pub const P256_KEY: &str = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
    krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";

/// RFC 6605 §6.1: the signature by [`P256_KEY`].
pub const P256_SIGNATURE: &str = "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
    yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==";

/// RFC 6605 §6.2: the P-384 key.
pub const P384_KEY: &str = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
    w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
    /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";

/// RFC 6605 §6.2: the signature by [`P384_KEY`].
pub const P384_SIGNATURE: &str = "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
    95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
    WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm";

/// RFC 8080 §6.1: the first Ed25519 key.
pub const ED25519_KEY_1: &str = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";

/// RFC 8080 §6.1: the signature by [`ED25519_KEY_1`].
pub const ED25519_SIGNATURE_1: &str = "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj
    H5GaMWeG96GUVZu6ECKOQmemHDg==";
// spellchecker:on
