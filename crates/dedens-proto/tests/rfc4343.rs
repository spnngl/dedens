//! RFC 4343: case-insensitive comparison, case preserved.

mod common;

use std::collections::HashSet;

use common::{name, name_of};
use dedens_proto::{MAX_NAME_LEN, Message, Name};
use proptest::prelude::*;

#[test]
fn s3_ascii_letters_compare_without_case() {
    assert_eq!(
        name_of(&[b"WWW", b"Example", b"COM"]),
        name_of(&[b"www", b"example", b"com"])
    );
}

#[test]
fn s3_only_ascii_letters_fold() {
    // 0xC9 is not the upper case of 0xE9 at the octet level, and `[` (0x5B) is not `{` (0x7B).
    assert_ne!(name_of(&[&[0xC9]]), name_of(&[&[0xE9]]));
    assert_ne!(name_of(&[b"["]), name_of(&[b"{"]));
}

#[test]
fn s3_label_boundaries_are_not_letters() {
    // `a.bc` and `ab.c` differ only in a length byte.
    assert_ne!(name_of(&[b"a", b"bc"]), name_of(&[b"ab", b"c"]));
}

#[test]
fn s3_case_is_preserved_through_decoding() {
    // A question for WwW.: the header with QDCOUNT 1, the name, type A, class IN.
    let wire = [
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'W', b'w', b'W', 0, 0, 1, 0, 1,
    ];
    let message = Message::decode(&wire).unwrap().message;
    let decoded = &message.questions[0].name;
    assert_eq!(decoded.to_wire(&mut [0; MAX_NAME_LEN]), &wire[12..17]);
    assert_eq!(decoded.to_string(), "WwW.");
}

#[test]
fn equal_names_hash_alike() {
    let set: HashSet<Name<'_>> = [name_of(&[b"EXAMPLE"]), name_of(&[b"example"])].into();
    assert_eq!(set.len(), 1);
}

proptest! {
    #[test]
    fn case_never_changes_identity(name in name()) {
        let flipped = Name::from_labels(name.labels().map(<[u8]>::to_ascii_uppercase).collect::<Vec<_>>().iter().map(Vec::as_slice))?;
        prop_assert_eq!(&flipped, &name);
        prop_assert_eq!(HashSet::from([flipped, name]).len(), 1);
    }
}
