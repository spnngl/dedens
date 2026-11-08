//! The workspace's shared test data (D161): the real responses, example zones and files of the root `testdata/`,
//! for the tests, benches, fuzz targets and simulations of every crate, and the helpers their tests share.
//!
//! A dev-dependency, but a dependency of `dedens-sim`, whose library code reads the data. The unit tests of
//! `dedens-proto` (in `src/`) get another build of the crate than this one links: they take paths and bytes from
//! here, never a `Name` or a `Message`; so do those of `dedens-net` with the `certificates` feature.
//!
//! By default the kit depends on `dedens-proto` alone. The feature `certificates` adds the TLS certificates of
//! the encrypted transports' tests, on `dedens-net`, compio and rcgen.

#[cfg(feature = "certificates")]
pub mod certificates;
pub mod dnssec;

use std::path::PathBuf;

use dedens_proto::{Message, Name, Record, ZoneEntry, ZoneReader};

/// The file or directory `relative` of the root `testdata/`, as `proto/a.bin` or `zones/`.
#[must_use]
pub fn path(relative: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata")).join(relative)
}

/// The response `case` of `testdata/proto/`, captured from a real server by `just capture`.
///
/// # Panics
///
/// When the file cannot be read.
#[must_use]
pub fn captured(case: &str) -> Vec<u8> {
    std::fs::read(path(&format!("proto/{case}.bin"))).expect("a captured response")
}

/// The message `wire` holds, as the captures do: decoded without a violation.
///
/// # Panics
///
/// When `wire` does not decode, or breaks a rule.
#[must_use]
#[track_caller]
pub fn message(wire: &[u8]) -> Message<'static> {
    let decoded = Message::decode(wire).expect("a message");
    assert_eq!(decoded.violations, [], "a capture breaks no rule");
    decoded.message.into_owned()
}

/// The bytes `text` writes in hexadecimal, as the RFCs print them: either case, split over lines and spaces.
///
/// # Panics
///
/// When `text` holds anything else, or an odd number of digits.
#[must_use]
pub fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| {
            c.to_digit(16)
                .and_then(|digit| u8::try_from(digit).ok())
                .expect("a hexadecimal digit")
        })
        .collect();
    assert!(digits.len().is_multiple_of(2), "an even number of digits");
    digits
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

/// The name of the dot-separated labels of `text`, the root for `""` or `"."`: no escapes, any byte of a label
/// kept as written.
///
/// # Panics
///
/// When a label or the name is too long.
#[must_use]
pub fn dns(text: &str) -> Name<'static> {
    Name::from_labels(text.split('.').filter(|l| !l.is_empty()).map(str::as_bytes))
        .expect("a valid name")
}

/// The records of the zone file `file` of `testdata/zones/`, its other entries left out.
///
/// # Panics
///
/// When the file cannot be read or is no valid zone.
#[must_use]
pub fn zone(file: &str) -> Vec<Record<'static>> {
    let text = std::fs::read(path("zones").join(file)).expect("zone file");
    ZoneReader::new(&text, None)
        .filter_map(|entry| match entry.expect("a valid zone") {
            ZoneEntry::Record(decoded) => Some(decoded.record),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_reads_either_case_over_lines() {
        assert_eq!(hex("00 fF\n 1a"), [0x00, 0xff, 0x1a]);
    }

    #[test]
    fn a_capture_is_a_message() {
        assert_eq!(
            message(&captured("a")).questions[0].name,
            dns("example.com")
        );
    }

    #[test]
    fn dns_reads_labels() {
        assert_eq!(dns("a.Example.").to_string(), "a.Example.");
        assert_eq!(dns(""), dns("."));
    }
}
