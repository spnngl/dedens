//! RFC 6672 §2.1: the RDATA of a DNAME is one domain name, never compressed.

use dedens_proto::Name;

#[test]
fn a_name_is_read_from_its_rdata_in_place() {
    let wire = b"\x03dev\x07example\x03com\x00";
    let name = Name::from_uncompressed(wire).expect("a name");
    assert_eq!(name.to_string(), "dev.example.com.");
    assert_eq!(
        name,
        "DEV.example.COM.".parse::<Name<'_>>().expect("a name")
    );
    let root = Name::from_uncompressed(b"\x00").expect("the root");
    assert!(root.is_root());
}

#[test]
fn bytes_that_are_not_one_name_are_refused() {
    for wire in [
        &b""[..],
        b"\x03dev",
        b"\x03dev\x00x",
        b"\x03dev\x00\x00",
        // A compression pointer: RFC 6672 §2.1 leaves no room for one.
        b"\x03dev\xc0\x00",
        b"\xc0\x00",
        // A label over 63 bytes.
        &[&[64][..], &[b'a'; 64], b"\x00"].concat(),
    ] {
        assert!(Name::from_uncompressed(wire).is_err(), "{wire:?}");
    }
}
