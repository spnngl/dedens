//! DNS over CoAP, the part before the transport: the request a DNS query makes, the path an SVCB record gives,
//! what a server makes of a request and of the DNS response it answers with, and the TTLs against Max-Age
//! (RFC 9953 §3.2, §4.2, §4.3).

use dedens_proto::DecodeError;
use dedens_proto::message::ttl_offsets;
use dedens_proto::rdata::{SvcParam, SvcParamKey, SvcParams};

use super::block::{self, BlockSize};
use super::exchange::Request;
use super::message::{Code, Message, OptionNumber, Options, Token, Type};

/// The longest TTL, 2^31 - 1 seconds (RFC 2181 §8).
const MAX_TTL: u32 = 0x7FFF_FFFF;

/// The largest block of a response, which a request may ask to be smaller.
pub const BLOCK_SIZE: BlockSize = BlockSize::MAX;

/// The path segments of the `docpath` parameter: none for the root path. None if there is no `docpath`: the
/// record does not describe a `DoC` server (RFC 9953 §3.2).
#[must_use]
pub fn docpath(params: &SvcParams<'_>) -> Option<Vec<Box<[u8]>>> {
    match params.get(SvcParamKey::DOCPATH)? {
        SvcParam::DocPath(segments) => Some(segments),
        // A key has one kind of parameter.
        _ => None,
    }
}

/// The request for the DNS `query` (a message of the wire format) to the resource at the path `docpath`: FETCH
/// with a Uri-Path option for each segment, the query as the body and its content format, `application/dns-message`,
/// as the one asked for (RFC 9953 §3.2, §4.2). The Uri-Host and Uri-Port options are left out, for the server
/// reached is the one named.
///
/// The DNS ID of the query should be 0, so that a CoAP cache may answer from an earlier query (RFC 9953 §4.2.2).
#[must_use]
pub fn request(docpath: &[Box<[u8]>], query: Vec<u8>, token: Token) -> Request {
    let mut options = Options::new();
    options.push_uri_path(docpath.iter().map(|segment| &**segment));
    options.set_content_format(Options::DNS_MESSAGE);
    options.set_accept(Options::DNS_MESSAGE);
    Request {
        code: Code::FETCH,
        options,
        payload: query,
        token,
    }
}

/// The segments of the URI path `path`, read as written without percent-decoding: none for `""` and `/`, an empty
/// one for each `//` and a trailing `/` after another segment (RFC 7252 §6.4).
#[must_use]
pub fn path_segments(path: &str) -> Vec<Box<[u8]>> {
    match path.strip_prefix('/') {
        None | Some("") => Vec::new(),
        Some(rest) => rest
            .split('/')
            .map(|segment| segment.as_bytes().into())
            .collect(),
    }
}

/// What a request to a `DoC` server asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Query<'a> {
    /// A DNS query, the body of the request.
    Dns(&'a [u8]),
    /// Another block of the response to an earlier query: a request with no body that asks for a block past the first
    /// (RFC 7959 §2.4). The clients that send the body with the first block only (libcoap, aiocoap) do it; the
    /// server finds the response again by [`Options::request_tag`] (see [`super::server::Blocks`]).
    Block,
}

/// What a server at the path `path` takes from `request`: the DNS query in the body of a FETCH or a POST with the
/// content format `application/dns-message` (RFC 9953 §4.2.1), or a request for a later block of a response with no
/// body. A GET, which RFC 9953 does not define, is refused with the other methods.
///
/// # Errors
///
/// The response code of the CoAP error (RFC 9953 §4.3.1), to answer with [`error`]: 4.04 for another path, 4.05
/// for another method, 4.02 for an unknown critical option, a query option or a bad block option, 4.15 for another
/// content format, 4.06 for another one accepted, 4.13 for a body sent in blocks, and 4.00 for no body unless it asks for a block past the first.
pub fn query<'a>(request: &'a Message, path: &[Box<[u8]>]) -> Result<Query<'a>, Code> {
    let options = &request.options;
    if !options.uri_path().eq(path.iter().map(|segment| &**segment)) {
        return Err(Code::NOT_FOUND);
    }
    if request.code != Code::FETCH && request.code != Code::POST {
        return Err(Code::METHOD_NOT_ALLOWED);
    }
    // The query is never in a Uri-Query option, which the server does not read.
    if request.unknown_critical().next().is_some()
        || options.get_all(OptionNumber::URI_QUERY).next().is_some()
    {
        return Err(Code::BAD_OPTION);
    }
    if options.content_format() != Some(Options::DNS_MESSAGE) {
        return Err(Code::UNSUPPORTED_CONTENT_FORMAT);
    }
    if options
        .accept()
        .is_some_and(|accepted| accepted != Options::DNS_MESSAGE)
    {
        return Err(Code::NOT_ACCEPTABLE);
    }
    match options.block1() {
        // A body in blocks is put together by a server keeping state (D81).
        Ok(Some(block)) if block.num() != 0 || block.more() => {
            return Err(Code::REQUEST_ENTITY_TOO_LARGE);
        }
        Ok(_) => {}
        Err(_) => return Err(Code::BAD_OPTION),
    }
    if request.payload.is_empty() {
        return match options.block2() {
            Ok(Some(block)) if block.num() != 0 => Ok(Query::Block),
            _ => Err(Code::BAD_REQUEST),
        };
    }
    Ok(Query::Dns(&request.payload))
}

/// The answer to `request` that carries the DNS response `dns` (RFC 9953 §4.3): 2.05 with the content format
/// `application/dns-message`, its Max-Age the least TTL of `dns`, subtracted from each TTL of it (§4.3.2); the
/// block the request asks for when `dns` is over [`BLOCK_SIZE`] or the request asks for blocks, Block2 (§4.3, RFC
/// 7959 §2.4), with the [`etag`] of the body. A block is cut from `dns` as it stands now, so the same query asked
/// block by block gets the same bodies as long as the answer does not change: the TTLs, less their least, do not.
///
/// A CON request gets an ACK carrying the response, a NON one a NON response with message ID `id` (RFC 7252
/// §5.2.3).
///
/// # Errors
///
/// 4.02 for a block past the end of the response, to answer with [`error`]; 5.00 for a `dns` that is not a DNS
/// message.
pub fn response(request: &Message, id: u16, mut dns: Vec<u8>) -> Result<Message, Code> {
    let max_age = take_max_age(&mut dns).map_err(|_| Code::INTERNAL_SERVER_ERROR)?;
    let requested = request.options.block2().map_err(|_| Code::BAD_OPTION)?;
    let slice = block::slice(&dns, requested, BLOCK_SIZE).map_err(|_| Code::BAD_OPTION)?;
    let mut reply = answer(request, id, Code::CONTENT);
    reply.options.set_content_format(Options::DNS_MESSAGE);
    reply.options.set_max_age(max_age);
    if let Some(block) = slice.block {
        reply.options.set_block2(block);
        reply.options.insert(OptionNumber::ETAG, etag(&dns));
    }
    reply.payload = slice.payload.to_vec();
    Ok(reply)
}

/// The `ETag` of the DNS response `dns`, as [`response`] cuts it into blocks (TTLs less their least, so not the
/// Max-Age): the FNV-1a hash of it, 8 bytes. A client putting blocks together compares it (RFC 7959 §2.4, RFC 7252
/// §5.10.6). It tells versions of a body apart, nothing more; an attacker who can forge it can forge the blocks.
/// The hash is written out, not `DefaultHasher`, whose algorithm may change with the compiler, so that servers of
/// two versions behind one address agree.
#[must_use]
pub fn etag(dns: &[u8]) -> [u8; 8] {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    dns.iter()
        .fold(OFFSET, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(PRIME)
        })
        .to_be_bytes()
}

/// The answer to `request` with the error `code` and no body (RFC 9953 §4.3.1), as [`response`] sends it.
#[must_use]
pub fn error(request: &Message, id: u16, code: Code) -> Message {
    answer(request, id, code)
}

/// A message answering `request` with `code`: an ACK of a CON, else a NON with message ID `id`.
fn answer(request: &Message, id: u16, code: Code) -> Message {
    let mut reply = Message::piggybacked(request, code);
    if request.kind != Type::Confirmable {
        reply.kind = Type::NonConfirmable;
        reply.id = id;
    }
    reply
}

/// Subtracts the least TTL of the DNS message `wire` from every TTL of it, and returns it: the Max-Age to send
/// (RFC 9953 §4.3.2). Without a record, 0, the answer being cached for no time. The OPT record has none.
///
/// # Errors
///
/// [`DecodeError`] when `wire` is not a DNS message.
pub fn take_max_age(wire: &mut [u8]) -> Result<u32, DecodeError> {
    let offsets = ttl_offsets_of(wire)?;
    let least = offsets
        .iter()
        .filter_map(|&at| ttl_at(wire, at))
        .min()
        .unwrap_or(0);
    map_ttls(wire, &offsets, |ttl| ttl.saturating_sub(least));
    Ok(least)
}

/// Adds `max_age` to every TTL of the DNS message `wire`, to a ceiling of 2^31 - 1: what a client does with the
/// Max-Age of a response (RFC 9953 §4.3.2).
///
/// # Errors
///
/// [`DecodeError`] when `wire` is not a DNS message.
pub fn add_max_age(wire: &mut [u8], max_age: u32) -> Result<(), DecodeError> {
    let offsets = ttl_offsets_of(wire)?;
    map_ttls(wire, &offsets, |ttl| {
        ttl.saturating_add(max_age).min(MAX_TTL)
    });
    Ok(())
}

/// The offsets of the TTLs of `wire`.
fn ttl_offsets_of(wire: &[u8]) -> Result<Vec<usize>, DecodeError> {
    let mut offsets = Vec::new();
    ttl_offsets(wire, |at| offsets.push(usize::from(at)))?;
    Ok(offsets)
}

/// The TTL at `at` in `wire`.
fn ttl_at(wire: &[u8], at: usize) -> Option<u32> {
    let bytes = wire.get(at..at + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

/// Sets each TTL of `offsets` to `new` of its value.
fn map_ttls(wire: &mut [u8], offsets: &[usize], new: impl Fn(u32) -> u32) {
    for &at in offsets {
        if let (Some(ttl), Some(bytes)) = (ttl_at(wire, at), wire.get_mut(at..at + 4)) {
            bytes.copy_from_slice(&new(ttl).to_be_bytes());
        }
    }
}
