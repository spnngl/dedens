//! Name Server Identifier option (RFC 5001 §2.3): empty in a query, opaque bytes in a response.

use crate::wire::Reader;

pub(super) fn decode(r: &mut Reader<'_>) -> Box<[u8]> {
    r.rest().into()
}
