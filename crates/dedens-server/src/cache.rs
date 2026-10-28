//! The cache stage: answers from `dedens-cache` before any later stage, stores what upstream answers, and holds
//! failures (D43).

use std::borrow::Cow;

use dedens_cache::{Cache, Freshness, Lookup, StalePolicy};
use dedens_proto::edns::{EdnsOption, ExtendedError, InfoCode};
use dedens_proto::{Edns, Header, Query, Rcode};

use crate::reply::Client;

/// Outcome of looking a query up.
pub(crate) enum Looked {
    /// The reply is in `out[..len]`; `refresh` asks to resolve the query again in the background.
    Reply { len: usize, refresh: bool },
    /// Resolution failed recently and the hold is on: SERVFAIL (RFC 9520 §3.2).
    Failed,
    /// The next stages resolve.
    Miss,
}

/// Looks `query` up in `cache` at `now` and writes the reply to `client` into `out`: the stored response patched
/// for the query, flags set as [`Client::reply`] sets them, and our OPT record when the client sent one, with EDE 3
/// (Stale Answer) or 19 (Stale NXDOMAIN Answer) on expired data (RFC 8767 §4, RFC 8914 §4.4).
///
/// Expired data answers as `stale` lets it: while resolving the query fails, or once the client's timer ran out
/// (RFC 8767 §5).
pub(crate) fn look(
    cache: &Cache,
    query: &Query<'_>,
    client: &Client<'_>,
    now: u32,
    stale: StalePolicy,
    out: &mut [u8],
) -> Looked {
    let limit = client.limit().min(out.len());
    // Room is kept for the larger OPT record, the stale one, since freshness is known only once found.
    let mut edns = client.edns.as_ref().map(|_| client.our_edns());
    if let Some(edns) = &mut edns {
        edns.options.push(EdnsOption::Ede(ExtendedError {
            code: InfoCode::STALE_ANSWER,
            text: Cow::Borrowed(""),
        }));
    }
    let Some(room) = limit.checked_sub(edns.as_ref().map_or(0, Edns::wire_len)) else {
        return Looked::Miss;
    };
    if room < Cache::MIN_OUT {
        return Looked::Miss;
    }
    let hit = match cache.lookup(query, now, stale, &mut out[..room]) {
        Lookup::Hit(hit) => hit,
        Lookup::Failed => return Looked::Failed,
        Lookup::Miss => return Looked::Miss,
    };
    client.patch_flags(&mut out[..hit.len]);
    let refresh = match hit.freshness {
        Freshness::Fresh { prefetch } => prefetch,
        Freshness::Stale => false,
    };
    let Some(mut edns) = edns else {
        return Looked::Reply {
            len: hit.len,
            refresh,
        };
    };
    match (hit.freshness, &mut edns.options[..]) {
        (Freshness::Stale, [EdnsOption::Ede(error)]) => {
            if Header::peek(out).is_some_and(|header| header.rcode == Rcode::NXDOMAIN) {
                error.code = InfoCode::STALE_NXDOMAIN_ANSWER;
            }
        }
        _ => edns.options.clear(),
    }
    match edns.append(&mut out[..limit], hit.len) {
        Ok(len) => Looked::Reply { len, refresh },
        Err(_) => Looked::Miss,
    }
}
