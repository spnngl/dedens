//! The `CoRE` Link Format (RFC 6690): the examples of §5, the attributes of §2 and §3, and the path a link names on the
//! server that sent it (D95).

use std::net::SocketAddr;

use dedens_net::coap::link::{Link, LinkError, parse};

const SERVER: &str = "192.0.2.1:5683";

fn server() -> SocketAddr {
    SERVER.parse().expect("a value")
}

fn links(payload: &str) -> Vec<Link> {
    parse(payload.as_bytes()).expect("a value")
}

fn targets(payload: &str) -> Vec<String> {
    links(payload).into_iter().map(|link| link.target).collect()
}

/// The path a link names, as text.
fn path(target: &str) -> Result<String, LinkError> {
    let link = Link {
        target: target.to_owned(),
        anchored: false,
        rel: Vec::new(),
        rt: Vec::new(),
        ct: Vec::new(),
    };
    link.path(server()).map(|path| {
        path.iter().fold(String::new(), |text, segment| {
            text + "/" + &String::from_utf8_lossy(segment)
        })
    })
}

/// RFC 6690 §5.1: two links, one per line.
#[test]
fn the_links_of_a_listing_per_line_are_read() {
    let text = "</sensors/temp>;if=\"sensor\",\n</sensors/light>;if=\"sensor\"";
    assert_eq!(targets(text), ["/sensors/temp", "/sensors/light"]);
    assert_eq!(
        targets("</sensors/temp>;if=\"sensor\",</sensors/light>;if=\"sensor\""),
        ["/sensors/temp", "/sensors/light"]
    );
}

/// RFC 6690 §5.2: a link with a content format.
#[test]
fn the_content_format_of_a_link_is_read() {
    let [link] = links("</sensors>;ct=40").try_into().expect("a value");
    assert_eq!(link.ct, [40]);
    assert_eq!(link.rt.len(), 0);
}

/// RFC 6690 §5.3: the resource type of each link.
#[test]
fn the_resource_types_of_links_are_read() {
    let text = "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\n</sensors/light>;rt=\"light-lux\";if=\"sensor\"";
    let found = links(text);
    assert_eq!(found[0].rt, ["temperature-c"]);
    assert_eq!(found[1].rt, ["light-lux"]);
}

/// RFC 6690 §5.4 and §3.1: an `rt` has several values, each a type.
#[test]
fn several_resource_types_in_one_value_are_read() {
    let [link] = links("</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"")
        .try_into()
        .expect("a value");
    assert_eq!(link.rt, ["light-lux", "core.sen-light"]);
}

/// RFC 6690 §5.5: a whole listing, with a title, an anchor and a `rel`; the links with an anchor are not the server's.
#[test]
fn a_whole_listing_with_anchors_is_read() {
    let text = "</sensors>;ct=40;title=\"Sensor Index\",\n\
                </sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\n\
                </sensors/light>;rt=\"light-lux\";if=\"sensor\",\n\
                <http://www.example.com/sensors/t123>;anchor=\"/sensors/temp\"\n\
                ;rel=\"describedby\",\n\
                </t>;anchor=\"/sensors/temp\";rel=\"alternate\"";
    let found = links(text);
    assert_eq!(found.len(), 5);
    assert_eq!(found[0].ct, [40]);
    assert_eq!(
        found.iter().map(Link::hosted).collect::<Vec<_>>(),
        [true, true, true, false, false]
    );
    assert_eq!(found[3].rel, ["describedby"]);
    assert_eq!(found[4].rel, ["alternate"]);
}

/// RFC 6690 §5.6: a size, which a client does not use and reads over.
#[test]
fn a_size_is_read_over() {
    let [link] = links("</firmware/v2.1>;rt=\"firmware\";sz=262144")
        .try_into()
        .expect("a value");
    assert_eq!(link.rt, ["firmware"]);
    assert_eq!(link.target, "/firmware/v2.1");
}

/// RFC 6690 §4: a server with no resource answers an empty payload.
#[test]
fn an_empty_payload_has_no_links() {
    assert_eq!(links("").len(), 0);
    assert_eq!(links(" \n").len(), 0);
}

/// RFC 6690 §2.2: a link with no `rel` has the relation `hosts`, one with another has not.
#[test]
fn a_link_hosts_unless_another_relation_or_an_anchor_says_not() {
    let found = links("</a>,</b>;rel=\"hosts\",</c>;rel=\"item\",</d>;anchor=\"/e\"");
    assert_eq!(
        found.iter().map(Link::hosted).collect::<Vec<_>>(),
        [true, true, false, false]
    );
}

/// RFC 6690 §3.1, §3.2, §3.3 and RFC 7252 §7.2.1: an attribute given once is not given twice.
#[test]
fn an_attribute_given_twice_is_refused() {
    for (text, name) in [
        ("</a>;rt=\"x\";rt=\"y\"", "rt"),
        ("</a>;if=\"x\";if=\"y\"", "if"),
        ("</a>;sz=1;sz=2", "sz"),
        ("</a>;ct=40;ct=41", "ct"),
    ] {
        assert_eq!(parse(text.as_bytes()), Err(LinkError::Repeated(name)));
    }
}

/// RFC 8288 §3.3: the first `rel` of a link is the one read.
#[test]
fn the_first_of_several_rel_is_read() {
    let [link] = links("</a>;rel=\"item\";rel=\"hosts\"")
        .try_into()
        .expect("a value");
    assert_eq!(link.rel, ["item"]);
}

/// RFC 6690 §2: what leaves the grammar is refused with its place.
#[test]
fn what_is_outside_the_grammar_is_refused() {
    for text in [
        "/a",
        "</a",
        "</a>;",
        "</a>;rt",
        "</a>;rt=",
        "</a>;rt=\"x",
        "</a>,",
        "</a> </b>",
        "</a>;ct=040",
        "</a>;sz=-1",
        "</a>;ct=65536",
        "</a>;rt=\"x  y\"",
    ] {
        assert!(parse(text.as_bytes()).is_err(), "{text:?} is accepted");
    }
    assert_eq!(parse(&[0xFF]), Err(LinkError::NotUtf8));
}

/// RFC 6690 §2.1: an attribute the reader does not know is checked and dropped; a quoted value has its escapes undone.
#[test]
fn an_unknown_attribute_is_dropped() {
    let [link] = links("</a>;title=\"a \\\"b\\\"\";obs;rt=\"core.dns\"")
        .try_into()
        .expect("a value");
    assert_eq!(link.rt, ["core.dns"]);
}

/// RFC 6690 §2.1: attribute names have no case.
#[test]
fn attribute_names_have_no_case() {
    let [link] = links("</a>;RT=\"core.dns\";CT=553")
        .try_into()
        .expect("a value");
    assert_eq!(link.rt, ["core.dns"]);
    assert_eq!(link.ct, [553]);
}

/// RFC 6690 §4 and RFC 3986 §5.2: a target resolves against `coap://server/.well-known/core`.
#[test]
fn a_target_resolves_against_the_well_known_uri() {
    assert_eq!(path("/dns/query").as_deref(), Ok("/dns/query"));
    assert_eq!(path("/").as_deref(), Ok(""));
    assert_eq!(path("dns").as_deref(), Ok("/.well-known/dns"));
    assert_eq!(path("../dns").as_deref(), Ok("/dns"));
    assert_eq!(path("/a/./b/../c").as_deref(), Ok("/a/c"));
    assert_eq!(
        path("coap://192.0.2.1/dns").as_deref(),
        Ok("/dns"),
        "the default port is the server's"
    );
    assert_eq!(path("coap://192.0.2.1:5683/dns").as_deref(), Ok("/dns"));
    assert_eq!(path("//192.0.2.1:5683/dns").as_deref(), Ok("/dns"));
}

/// RFC 7252 §6.4: the segments of a path are the bytes their percent-encodings stand for; the dot segments are removed
/// before (RFC 3986 §6.2.2.2), and an encoded `/` is a byte of a segment, not a delimiter.
#[test]
fn a_target_is_percent_decoded_by_segment() {
    assert_eq!(path("/d%20ns/%C3%A9").as_deref(), Ok("/d ns/é"));
    assert_eq!(path("/a%2Fb/c").as_deref(), Ok("/a/b/c"), "shown as text");
    let link = Link {
        target: "/a%2Fb/c".to_owned(),
        anchored: false,
        rel: Vec::new(),
        rt: Vec::new(),
        ct: Vec::new(),
    };
    let segments = link.path(server()).expect("a value");
    assert_eq!(segments.len(), 2);
    assert_eq!(&*segments[0], b"a/b");
    assert_eq!(path("/%41").as_deref(), Ok("/A"));
}

/// A client acts on a link only for the server that sent it: another host, port or scheme is refused, as is a query, a
/// fragment, a percent-encoding that is no byte and one that makes a dot segment (RFC 7252 §5.10.1).
#[test]
fn a_target_that_is_not_a_path_on_the_server_is_refused() {
    for target in [
        "coap://192.0.2.2/dns",
        "coap://192.0.2.1:5684/dns",
        "coap://dns.example/dns",
        "//192.0.2.2/dns",
        "coaps://192.0.2.1/dns",
        "http://192.0.2.1/dns",
        "/dns?dns=x",
        "/dns#x",
        "/%zz",
        "/a/%2",
        "/%2E%2e",
        "/a/%2e",
    ] {
        assert!(
            matches!(path(target), Err(LinkError::Target { .. })),
            "{target} is accepted"
        );
    }
}
