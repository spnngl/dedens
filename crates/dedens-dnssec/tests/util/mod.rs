//! Helpers of the RFC tests: records and `RRsets` built by hand from the examples' text, so that no test relies
//! on code under test. The examples themselves and the data an RRSIG signs (RFC 4034 §3.1.8.1) are in
//! `dedens_testkit::dnssec`.

use dedens_dnssec::crypto::Budget;
use dedens_dnssec::rrsig::{self, Key, RrSet, SigError, Signature, Verified};
use dedens_proto::{MAX_NAME_LEN, Message, Name, Record};
use dedens_testkit::dnssec::{Rrsig, b64, canonical_name};

pub(crate) mod denial;

// spellchecker:off
/// RFC 4034 §5.4: the key of `dskey.example.com.` (algorithm 5, key tag 60485), the DNSKEY that RFC 4034 and
/// RFC 4509 give a DS for.
pub(crate) const DSKEY: &str = "AQOeiiR0GOMYkDshWoSKz9Xz
    fwJr1AYtsmx3TGkJaNXVbfi/
    2pHm822aJ5iI9BMzNXxeYCmZ
    DRD99WYwYqUSdjMmmAphXdvx
    egXd/M5+X7OrzKBaMbCVdFLU
    Uh6DhweJBjEVv5f2wwjM9Xzc
    nOf+EPbtG9DMBmADjFDc2w/r
    ljwvFw==";
// spellchecker:on

/// A name in presentation format.
pub(crate) fn name(text: &str) -> Name<'static> {
    text.parse().expect("a name")
}

/// The records of one owner and type, class IN, as a decoder reads them from the answer of a message built by
/// hand with `rdatas` as given (names inside them in any case): none when the message does not decode cleanly.
pub(crate) fn try_records(
    owner: &str,
    rtype: u16,
    ttl: u32,
    rdatas: &[Vec<u8>],
) -> Option<Vec<Record<'static>>> {
    try_records_in(1, owner, rtype, ttl, rdatas)
}

/// [`try_records`] of class `class` (1 is IN).
pub(crate) fn try_records_in(
    class: u16,
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
        wire.extend(class.to_be_bytes());
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
pub(crate) fn records(
    owner: &str,
    rtype: u16,
    ttl: u32,
    rdatas: &[Vec<u8>],
) -> Vec<Record<'static>> {
    try_records(owner, rtype, ttl, rdatas).expect("decodes without a violation")
}

/// Whether `sigs` sign `rrset` under `keys` at `now`, with the default budget.
pub(crate) fn check(
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

/// An `RRset` of class `class` (1 is IN), as [`rrset`].
pub(crate) fn rrset_in(class: u16, owner: &str, rtype: u16, rdatas: &[Vec<u8>]) -> RrSet<'static> {
    let records = try_records_in(class, owner, rtype, 3600, rdatas).expect("decodes");
    RrSet::group(&records).pop().expect("one RRset")
}

/// An `RRset` of the records `rdatas` at `owner`, TTL 3600.
pub(crate) fn rrset(owner: &str, rtype: u16, rdatas: &[Vec<u8>]) -> RrSet<'static> {
    RrSet::group(&records(owner, rtype, 3600, rdatas))
        .pop()
        .expect("one RRset")
}

/// The RRSIG record of `rrsig` over `owner`'s `RRset`, with its signature in base64, as an `RRset` (TTL 3600).
pub(crate) fn rrsig_set(owner: &str, rrsig: &Rrsig<'_>, signature: &str) -> RrSet<'static> {
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
