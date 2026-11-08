//! The workspace's shared test data (D161): the real responses, example zones and files of the root `testdata/`,
//! for the tests, benches, fuzz targets and simulations of every crate, and the helpers their tests share.
//!
//! A dev-dependency, but a dependency of `dedens-sim`, whose library code reads the data. The unit tests of
//! `dedens-proto` (in `src/`) get another build of the crate than this one links: they take paths and bytes from
//! here, never a `Name` or a `Message`.

use std::path::PathBuf;

use dedens_proto::Name;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_reads_either_case_over_lines() {
        assert_eq!(hex("00 fF\n 1a"), [0x00, 0xff, 0x1a]);
    }

    #[test]
    fn dns_reads_labels() {
        assert_eq!(dns("a.Example.").to_string(), "a.Example.");
        assert_eq!(dns(""), dns("."));
    }
}
