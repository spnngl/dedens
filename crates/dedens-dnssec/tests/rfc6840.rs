//! RFC 6840 §5.1 (the canonical form of RDATA, correcting RFC 4034 §6.2) and §5.11 (an RRSIG over an `RRset`
//! of any type): which names of RDATA a signer lowercases.

mod common;

use common::{canonical_name, name, rrset};

/// A name in wire form, in the case given.
fn wire(text: &str) -> Vec<u8> {
    name(text).to_wire(&mut [0; 255]).to_vec()
}

/// RDATA made of `parts`, joined.
fn rdata(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// The one canonical RDATA of `rtype` at `owner` made of `rdata`.
fn canonical(rtype: u16, rdata: Vec<u8>) -> Vec<u8> {
    let mut rdatas = rrset("owner.example.", rtype, &[rdata]).canonical_rdatas();
    assert_eq!(rdatas.len(), 1);
    rdatas.pop().expect("one RDATA")
}

#[test]
fn the_names_of_rfc_4034_6_2_are_lowercased() {
    let mixed = wire("Mail.EXAMPLE.");
    let lower = canonical_name("mail.example.");
    let preference = 10_u16.to_be_bytes();
    // (type, RDATA with the name in any case, the same in lower case)
    let cases: Vec<(u16, Vec<u8>, Vec<u8>)> = vec![
        // NS, CNAME, PTR, DNAME (RFC 6672 §2.2 keeps it in §6.2's list).
        (2, mixed.clone(), lower.clone()),
        (5, mixed.clone(), lower.clone()),
        (12, mixed.clone(), lower.clone()),
        (39, mixed.clone(), lower.clone()),
        // MX, and KX (RFC 2230) which has the same layout.
        (
            15,
            rdata(&[&preference, &mixed]),
            rdata(&[&preference, &lower]),
        ),
        (
            36,
            rdata(&[&preference, &mixed]),
            rdata(&[&preference, &lower]),
        ),
        // SOA: two names, then five 32-bit numbers.
        (
            6,
            rdata(&[&mixed, &wire("Admin.EXAMPLE."), &[0; 20]]),
            rdata(&[&lower, &canonical_name("admin.example."), &[0; 20]]),
        ),
        // SRV: priority, weight and port, then the target.
        (
            33,
            rdata(&[&[0, 1, 0, 2, 0, 80], &mixed]),
            rdata(&[&[0, 1, 0, 2, 0, 80], &lower]),
        ),
        // NXT (RFC 2535): the next name and a bitmap.
        (
            30,
            rdata(&[&mixed, &[0b0100_0000]]),
            rdata(&[&lower, &[0b0100_0000]]),
        ),
    ];
    for (rtype, given, expected) in cases {
        assert_eq!(canonical(rtype, given), expected, "type {rtype}");
    }
}

#[test]
fn naptr_replacement_is_lowercased_but_its_strings_are_not() {
    // RFC 4034 §6.2 lists NAPTR; its flags, service and regexp are character strings, not names.
    let strings = b"\x01S\x07SIP+D2U\x05!^.*$";
    let given = rdata(&[&[0, 10, 0, 20], strings, &wire("_SIP._UDP.Example.")]);
    let expected = rdata(&[
        &[0, 10, 0, 20],
        strings,
        &canonical_name("_sip._udp.example."),
    ]);
    assert_eq!(canonical(35, given), expected);
}

#[test]
fn the_next_name_of_an_nsec_keeps_its_case() {
    // RFC 6840 §5.1: RFC 4034 §6.2 listed NSEC, but signers never lowercased it.
    let given = rdata(&[&wire("Next.EXAMPLE."), &[0, 1, 0b0100_0000]]);
    assert_eq!(canonical(47, given.clone()), given);
}

#[test]
fn the_signer_of_an_rrsig_is_lowercased() {
    // RFC 6840 §5.1: the signer's name of an RRSIG, when an `RRset` of RRSIG records is itself signed.
    let fixed = [0_u8; 18];
    let signature = [0xAB_u8; 8];
    let given = rdata(&[&fixed, &wire("Signer.EXAMPLE."), &signature]);
    let expected = rdata(&[&fixed, &canonical_name("signer.example."), &signature]);
    assert_eq!(canonical(46, given), expected);
}

#[test]
fn hinfo_and_txt_have_no_names() {
    // RFC 6840 §5.1: HINFO is two character strings, so letters in them stay as they are.
    let hinfo = b"\x05INTEL\x05Linux".to_vec();
    assert_eq!(canonical(13, hinfo.clone()), hinfo);
    let txt = b"\x09Mail.COM.".to_vec();
    assert_eq!(canonical(16, txt.clone()), txt);
}

#[test]
fn an_unknown_type_is_left_alone() {
    // RFC 3597 §4: no name of an unknown type is lowercased; RFC 6840 §5.11 has the signature cover it all the
    // same.
    let given = wire("Mail.EXAMPLE.");
    assert_eq!(canonical(65400, given.clone()), given);
}

#[test]
fn the_records_are_sorted_after_their_names_are_lowercased() {
    // §6.3: the order is that of the canonical RDATA, `B.Example.` after `a.example.`.
    let set = rrset("WWW.Example.", 2, &[wire("B.Example."), wire("a.example.")]);
    assert_eq!(
        set.canonical_rdatas(),
        [canonical_name("a.example."), canonical_name("b.example.")]
    );
}
