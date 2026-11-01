//! The `parse_link_format` target: the reader of the `CoRE` Link Format (RFC 6690) on arbitrary bytes, and the list
//! the `dedensd` listener writes read back (D95).

use std::net::SocketAddr;

use dedens_net::coap::link::{Link, parse};
use dedens_net::coap::{Code, Message, Options, Token, Type, doc};

/// Both families, and a port that is not the default one.
const SERVERS: [([u8; 4], u16); 2] = [([192, 0, 2, 1], 5683), ([127, 0, 0, 1], 40000)];

/// A path a client takes from a link is a path as `dedensd` reads one: its segments hold no `/`, `?`, `#` or `%`,
/// and none is a dot segment, which the resolution removes (RFC 3986 §5.2.4).
fn check_path(link: &Link, server: SocketAddr) {
    let Ok(path) = link.path(server) else {
        return;
    };
    for segment in &path {
        assert!(
            !segment.contains(&b'/')
                && !segment.contains(&b'?')
                && !segment.contains(&b'#')
                && !segment.contains(&b'%'),
            "{:?} holds a delimiter",
            String::from_utf8_lossy(segment)
        );
        assert!(
            &**segment != b"." && &**segment != b"..",
            "a dot segment is left"
        );
    }
}

/// The links of arbitrary bytes, and each link's path on a server: never a panic, and a path is a path. Then the same
/// bytes as the segments of the path of a `DoC` resource, split at `/` (but for a dot segment, which a Uri-Path is not,
/// RFC 7252 §5.10.1): the list the server writes for it is read back as one hosted link of type `core.dns` and content
/// format 553 whose path is the one the server holds.
///
/// # Panics
///
/// On a bug in the reader, or in the writer of the list.
pub fn parse_link_format(data: &[u8]) {
    for (ip, port) in SERVERS {
        let server = SocketAddr::from((ip, port));
        if let Ok(links) = parse(data) {
            for link in &links {
                let _ = link.hosted();
                check_path(link, server);
            }
        }
    }
    let path: Vec<Box<[u8]>> = if data.is_empty() {
        Vec::new()
    } else {
        data.split(|&byte| byte == b'/').map(Into::into).collect()
    };
    if path
        .iter()
        .any(|segment| &**segment == b"." || &**segment == b"..")
    {
        return;
    }
    let mut options = Options::new();
    options.push_uri_path([b".well-known".as_slice(), b"core"]);
    let request = Message {
        kind: Type::Confirmable,
        code: Code::GET,
        id: 1,
        token: Token::new(&[]).expect("an empty token"),
        options,
        payload: Vec::new(),
    };
    let reply = doc::discovery(&request, 1, &path).expect("a request for the list is answered");
    assert_eq!(reply.code, Code::CONTENT);
    let links = parse(&reply.payload).unwrap_or_else(|e| {
        panic!(
            "the list {:?} for the path {path:?} reads: {e}",
            String::from_utf8_lossy(&reply.payload)
        )
    });
    let [link] = links.as_slice() else {
        panic!("one link, not {}", links.len());
    };
    assert!(link.hosted(), "the link is the server's own");
    assert_eq!(link.rt, ["core.dns"]);
    assert_eq!(link.ct, [Options::DNS_MESSAGE]);
    for (ip, port) in SERVERS {
        let read = link.path(SocketAddr::from((ip, port)));
        assert_eq!(
            read.as_deref(),
            Ok(path.as_slice()),
            "the list {:?} names another path",
            String::from_utf8_lossy(&reply.payload)
        );
    }
}
