//! Canonical form of names and RDATA (RFC 4034 §6.2, RFC 6840 §5.1).

use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{Name, RecordType};

/// One field of RDATA that matters to the canonical form.
#[derive(Clone, Copy)]
enum Field {
    /// A domain name, lowercased.
    Domain,
    /// Bytes kept as they are.
    Skip(usize),
    /// A character string, kept as it is.
    CharString,
}

use Field::{CharString, Domain, Skip};

/// The fields of RDATA up to its last name; what follows is kept as it is.
///
/// The types of RFC 4034 §6.2 item 3, less what RFC 6840 §5.1 corrects: NSEC's next name is not lowercased,
/// RRSIG's signer is, HINFO has no name. Opaque types are in it (DNAME, KX, the types of RFC 3597 §4) as
/// `dedens-proto` has no layout for them that may not be compressed. A6 is historic (RFC 6563) and is left out,
/// as Unbound does.
const fn layout(rtype: RecordType) -> &'static [Field] {
    match rtype {
        RecordType::NS
        | RecordType::MD
        | RecordType::MF
        | RecordType::CNAME
        | RecordType::MB
        | RecordType::MG
        | RecordType::MR
        | RecordType::PTR
        | RecordType::DNAME
        | RecordType::NXT => &[Domain],
        RecordType::SOA | RecordType::MINFO | RecordType::RP => &[Domain, Domain],
        RecordType::MX | RecordType::AFSDB | RecordType::RT | RecordType::KX => &[Skip(2), Domain],
        RecordType::SRV => &[Skip(6), Domain],
        RecordType::PX => &[Skip(2), Domain, Domain],
        RecordType::NAPTR => &[Skip(4), CharString, CharString, CharString, Domain],
        RecordType::SIG | RecordType::RRSIG => &[Skip(18), Domain],
        _ => &[],
    }
}

/// `wire`, the RDATA of `rtype`, uncompressed, with the names the canonical form lowercases lowercased.
///
/// RDATA too short for its layout is kept as far as it is readable: no signature can match it.
pub(super) fn rdata(rtype: RecordType, wire: &[u8]) -> Vec<u8> {
    let mut out = wire.to_vec();
    let mut pos = 0;
    for field in layout(rtype) {
        let Some(rest) = out.get_mut(pos..) else {
            break;
        };
        let len = match field {
            Domain => {
                let len = name_len(rest);
                if let Some(name) = len.and_then(|len| rest.get_mut(..len)) {
                    name.make_ascii_lowercase();
                }
                len
            }
            Skip(len) => Some(*len),
            CharString => rest.first().map(|&len| usize::from(len) + 1),
        };
        let Some(len) = len else {
            break;
        };
        pos += len;
    }
    out
}

/// The length of the uncompressed name at the start of `wire`, root label included; `None` when it is cut or
/// holds a pointer.
fn name_len(wire: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        let label = usize::from(*wire.get(pos)?);
        pos += 1 + label;
        if label == 0 {
            return Some(pos);
        }
        // A pointer or an extended label: 64 and above.
        if label > dedens_proto::name::MAX_LABEL_LEN {
            return None;
        }
    }
}

/// The wire form of `name` with every letter lowercased: label lengths are 63 or less, so no length byte is one.
pub(super) fn owner(name: &Name<'_>) -> Vec<u8> {
    let mut wire = name.to_wire(&mut [0; MAX_NAME_LEN]).to_vec();
    wire.make_ascii_lowercase();
    wire
}
