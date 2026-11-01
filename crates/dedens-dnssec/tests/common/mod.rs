//! Helpers of the RFC tests: the examples' text decoded, and the data an RRSIG signs (RFC 4034 §3.1.8.1)
//! built by hand from it, so that no test relies on code under test.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses a subset of a shared module"
)]

use data_encoding::{BASE64, HEXLOWER_PERMISSIVE};
use dedens_proto::Name;
use dedens_proto::name::MAX_NAME_LEN;

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
