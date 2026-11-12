//! The cache stage: answers from `dedens-cache` before any later stage, stores what upstream answers, and holds
//! failures (D43).

use dedens_cache::{Cache, Checked, Freshness, Lookup, StalePolicy};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Header, Query, Rcode};

use crate::reply::Client;

/// How [`look`] reads the cache.
#[derive(Clone, Copy)]
pub(crate) enum Read {
    /// A query asked: a use of its entry; expired data answers as the policy lets it.
    Lookup(StalePolicy),
    /// The response just stored for the query, served without counting a use ([`Cache::stored`]).
    Stored,
}

/// Outcome of looking a query up.
pub(crate) enum Looked {
    /// The reply is in `out[..len]`; `refresh` asks to resolve the query again in the background. `mark` is the one
    /// the entry carries (`Cache::insert`), `truncated` whether the reply lost records to the client's limit.
    Reply {
        len: usize,
        refresh: bool,
        mark: u64,
        truncated: bool,
    },
    /// Resolution failed recently and the hold is on: SERVFAIL (RFC 9520 §3.2).
    Failed,
    /// The entry is an answer that failed validation, for a client that did not disable checking: SERVFAIL with
    /// this error (RFC 4035 §3.2.2, §4.7, D77).
    Bogus(InfoCode),
    /// The next stages resolve.
    Miss,
    /// The next stages resolve; expired data is kept and may answer once the client's timer runs out (RFC 8767 §5).
    Expired,
}

/// Looks `query` up in `cache` at `now` and writes the reply to `client` into `out`: the stored response patched
/// for the query by the cache, flags included (AA and Z clear, RA set, the client's RD and CD, AD as RFC 6840 §5.8
/// says), and our OPT record when the client sent one, with EDE 3
/// (Stale Answer) or 19 (Stale NXDOMAIN Answer) on expired data (RFC 8767 §4, RFC 8914 §4.4).
///
/// Expired data answers as a [`Read::Lookup`] policy lets it: while resolving the query fails, or once the
/// client's timer ran out (RFC 8767 §5).
pub(crate) fn look(
    cache: &Cache,
    query: &Query<'_>,
    client: &Client<'_>,
    now: u32,
    read: Read,
    out: &mut [u8],
) -> Looked {
    let limit = client.limit().min(out.len());
    let edns = client.has_opt().then(|| client.our_edns());
    // Room is kept for our OPT record; a stale hit leaves room for its EDE option itself (`Cache::STALE_ROOM`).
    let opt = edns
        .as_ref()
        .map_or(0, |edns| edns.wire_len() + client.options_len(None));
    let Some(room) = limit.checked_sub(opt) else {
        return Looked::Miss;
    };
    if room < Cache::MIN_OUT {
        return Looked::Miss;
    }
    let found = match read {
        Read::Lookup(stale) => cache.lookup(query, now, stale, &mut out[..room]),
        Read::Stored => cache
            .stored(query, now, &mut out[..room])
            .map_or(Lookup::Miss, Lookup::Hit),
    };
    let hit = match found {
        Lookup::Hit(hit) => hit,
        Lookup::Failed => return Looked::Failed,
        Lookup::Miss => return Looked::Miss,
        Lookup::Expired => return Looked::Expired,
    };
    if let Checked::Bogus(code) = hit.checked {
        return Looked::Bogus(code);
    }
    let refresh = match hit.freshness {
        Freshness::Fresh { prefetch } => prefetch,
        Freshness::Stale => false,
    };
    let Some(edns) = edns else {
        return Looked::Reply {
            len: hit.len,
            refresh,
            mark: hit.mark,
            truncated: hit.truncated,
        };
    };
    let error = (hit.freshness == Freshness::Stale).then(|| {
        if Header::peek(out).is_some_and(|header| header.rcode == Rcode::NXDOMAIN) {
            InfoCode::STALE_NXDOMAIN_ANSWER
        } else {
            InfoCode::STALE_ANSWER
        }
    });
    match client.append_opt(&edns, error, &mut out[..limit], hit.len) {
        Some(len) => Looked::Reply {
            len,
            refresh,
            mark: hit.mark,
            truncated: hit.truncated,
        },
        None => Looked::Miss,
    }
}
