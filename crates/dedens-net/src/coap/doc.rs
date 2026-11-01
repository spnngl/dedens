//! DNS over CoAP, the part before the transport: the request a DNS query makes and the path an SVCB record
//! gives (RFC 9953 §3.2, §4.2).

use dedens_proto::rdata::{SvcParam, SvcParamKey, SvcParams};

use super::exchange::Request;
use super::message::{Code, Options, Token};

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
