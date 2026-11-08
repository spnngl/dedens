//! RFC 4509 (SHA-256 in DS records) §2.3, and the DS of the root's KSK that RFC 9718 §2 lists (algorithm 8, SHA-256).

mod common;

use common::{DSKEY, name};
use dedens_dnssec::crypto::{ds_digest, key_tag};
use dedens_proto::DigestType;
use dedens_testkit::dnssec::dnskey_rdata;
use dedens_testkit::hex;

// RFC 9718 §2: `. IN DNSKEY 257 3 8`, the KSK-2017 (key tag 20326).
const ROOT_KSK: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3
    +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv
    ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF
    0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e
    oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd
    RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN
    R1AkUTV74bU=";

#[test]
fn sha256_ds_of_the_rfc_example() {
    // §2.3: `dskey.example.com. 86400 IN DS 60485 5 2 ( D4B7D520... )`.
    let owner = name("dskey.example.com.");
    let digest =
        ds_digest(DigestType::SHA256, &owner, &dnskey_rdata(256, 5, DSKEY)).expect("SHA-256");
    assert_eq!(
        digest.as_ref(),
        hex("D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A")
    );
}

#[test]
fn sha256_ds_of_the_root_ksk() {
    let rdata = dnskey_rdata(257, 8, ROOT_KSK);
    assert_eq!(key_tag(&rdata), 20326);
    let digest = ds_digest(DigestType::SHA256, &name("."), &rdata).expect("SHA-256");
    assert_eq!(
        digest.as_ref(),
        hex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
    );
}

#[test]
fn a_digest_of_another_key_differs() {
    let owner = name("dskey.example.com.");
    let one = ds_digest(DigestType::SHA256, &owner, &dnskey_rdata(256, 5, DSKEY)).expect("SHA-256");
    let other =
        ds_digest(DigestType::SHA256, &owner, &dnskey_rdata(257, 5, DSKEY)).expect("SHA-256");
    assert_ne!(one, other);
}
