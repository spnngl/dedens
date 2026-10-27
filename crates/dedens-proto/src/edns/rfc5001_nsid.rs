//! Name Server Identifier option (RFC 5001 §2.3): empty in a query, opaque bytes in a response.

use std::borrow::Cow;

use crate::wire::Reader;

pub(super) fn decode<'a>(r: &mut Reader<'a>) -> Cow<'a, [u8]> {
    Cow::Borrowed(r.rest())
}
