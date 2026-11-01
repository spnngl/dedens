//! The `CoRE` Link Format (RFC 6690), read: the links of `/.well-known/core`, and the path a link names on the server
//! that sent it (D95).
//!
//! The reader takes the grammar of RFC 6690 §2 and refuses what is not in it, with its place and reason: a client
//! acting on links must not guess. Whitespace around `;`, `,` and `=` is read over (the RFC converts a header to this
//! format by removing it, and its examples break lines). Attributes it does not know are checked for syntax and
//! dropped.

use std::net::{IpAddr, SocketAddr};

use super::doc::path_segments;

/// The port of a `coap` URI without one (RFC 7252 §6.1).
const COAP_PORT: u16 = 5683;

/// The path of the resource links are asked of, and the one relative references are resolved against (RFC 6690 §4).
const WELL_KNOWN: &str = "/.well-known/core";

/// What a link of the format says: its target and the attributes that tell a client what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The URI reference between `<` and `>`.
    pub target: String,
    /// Whether the link has an `anchor`: it then relates another resource, not one the server hosts (RFC 6690 §2.3).
    pub anchored: bool,
    /// The values of `rel`, none when it is absent: the link then has the relation `hosts` (RFC 6690 §2.2).
    pub rel: Vec<String>,
    /// The values of `rt`, the resource types (RFC 6690 §3.1).
    pub rt: Vec<String>,
    /// The values of `ct`, the content formats the resource may return (RFC 7252 §7.2.1).
    pub ct: Vec<u16>,
}

/// Why a payload is not in the link format, or a link names nothing the client may ask.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The payload is not UTF-8 (RFC 6690 §2).
    #[error("not UTF-8")]
    NotUtf8,
    /// The payload leaves the grammar of RFC 6690 §2 at this byte.
    #[error("expected {expected} at byte {at}")]
    Syntax {
        /// What the grammar allows here.
        expected: &'static str,
        /// The offset of the byte.
        at: usize,
    },
    /// An attribute that RFC 6690 §3 allows once in a link is given twice.
    #[error("`{0}` is given more than once in a link")]
    Repeated(&'static str),
    /// The value of an attribute is not what its definition says.
    #[error("`{attribute}` is not {expected}")]
    Value {
        /// The attribute.
        attribute: &'static str,
        /// What its value is.
        expected: &'static str,
    },
    /// The target of a link is no path on the server that sent it.
    #[error("link target `{target}`: {reason}")]
    Target {
        /// The URI reference.
        target: String,
        /// Why it is refused.
        reason: &'static str,
    },
}

impl Link {
    /// Whether the link says its target is hosted by the server: no `anchor`, and no `rel` or one that has `hosts`
    /// (RFC 6690 §2.2, §2.3).
    #[must_use]
    pub fn hosted(&self) -> bool {
        !self.anchored && (self.rel.is_empty() || self.rel.iter().any(|rel| rel == "hosts"))
    }

    /// The path segments of the target, resolved (RFC 3986 §5.2) against `coap://{server}/.well-known/core`, the URI
    /// the links were read from: none for the root path.
    ///
    /// Only a path on the server itself, which the address says: a target with another scheme than `coap` or
    /// another authority than the server's IP address and port (a name is not compared: it may be anywhere), a
    /// query or a fragment is refused. Each segment is percent-decoded, as the URI of a request is (RFC 7252 §6.4
    /// step 8), after the dot segments are removed (RFC 3986 §6.2.2.2); one that decodes to `.` or `..` is refused, as
    /// a Uri-Path is never one (RFC 7252 §5.10.1).
    ///
    /// # Errors
    ///
    /// [`LinkError::Target`] for a target that names no such path.
    pub fn path(&self, server: SocketAddr) -> Result<Vec<Box<[u8]>>, LinkError> {
        resolve(&self.target, server)
            .and_then(|path| {
                path_segments(&path)
                    .iter()
                    .map(|segment| decode(segment))
                    .collect()
            })
            .map_err(|reason| LinkError::Target {
                target: self.target.clone(),
                reason,
            })
    }
}

/// The links of `payload`, a `/.well-known/core` representation: none for the empty payload (RFC 6690 §4).
///
/// An `rt`, `if`, `sz` or `ct` given twice in a link is refused (RFC 6690 §3.1-3.3; one `ct`, RFC 7252 §7.2.1),
/// a `rel` given twice has its first read (RFC 8288 §3.3, as RFC 5988 §5.3 says). An `rt` value is not checked
/// against the grammar of a relation type, which it calls opaque (RFC 6690 §3.1).
///
/// # Errors
///
/// [`LinkError`] for a payload outside the grammar, or an attribute with a value it cannot have.
pub fn parse(payload: &[u8]) -> Result<Vec<Link>, LinkError> {
    let text = std::str::from_utf8(payload).map_err(|_| LinkError::NotUtf8)?;
    let mut reader = Reader {
        whole: text.len(),
        rest: text,
    };
    let mut links = Vec::new();
    reader.skip_space();
    if reader.rest.is_empty() {
        return Ok(links);
    }
    loop {
        links.push(reader.link()?);
        reader.skip_space();
        if reader.rest.is_empty() {
            return Ok(links);
        }
        reader.expect(',', "`,` or the end of the links")?;
        reader.skip_space();
    }
}

/// The text left to read.
struct Reader<'a> {
    /// The length of the whole text, to tell the offset.
    whole: usize,
    rest: &'a str,
}

impl<'a> Reader<'a> {
    fn error(&self, expected: &'static str) -> LinkError {
        LinkError::Syntax {
            expected,
            at: self.whole - self.rest.len(),
        }
    }

    fn skip_space(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\t', '\r', '\n']);
    }

    fn eat(&mut self, c: char) -> bool {
        match self.rest.strip_prefix(c) {
            Some(rest) => {
                self.rest = rest;
                true
            }
            None => false,
        }
    }

    fn expect(&mut self, c: char, expected: &'static str) -> Result<(), LinkError> {
        if self.eat(c) {
            Ok(())
        } else {
            Err(self.error(expected))
        }
    }

    /// The longest run of characters that `allowed` accepts, at least one.
    fn run(
        &mut self,
        allowed: impl Fn(char) -> bool,
        expected: &'static str,
    ) -> Result<&'a str, LinkError> {
        let end = self.rest.find(|c| !allowed(c)).unwrap_or(self.rest.len());
        if end == 0 {
            return Err(self.error(expected));
        }
        let (run, rest) = self.rest.split_at(end);
        self.rest = rest;
        Ok(run)
    }

    /// `link-value`: the target and the parameters after it, up to a `,` or the end.
    fn link(&mut self) -> Result<Link, LinkError> {
        self.expect('<', "`<`")?;
        let (target, rest) = self.rest.split_once('>').ok_or_else(|| self.error("`>`"))?;
        self.rest = rest;
        let mut link = Link {
            target: target.to_owned(),
            anchored: false,
            rel: Vec::new(),
            rt: Vec::new(),
            ct: Vec::new(),
        };
        let mut given: Vec<&'static str> = Vec::new();
        loop {
            self.skip_space();
            if !self.eat(';') {
                return Ok(link);
            }
            self.skip_space();
            let name = self.name()?;
            self.skip_space();
            let value = if self.eat('=') {
                self.skip_space();
                Some(self.value()?)
            } else {
                None
            };
            link.attribute(&name.to_ascii_lowercase(), value.as_deref(), &mut given)?;
        }
    }

    /// `parmname`, with the `*` of an extension name (RFC 6690 §2).
    fn name(&mut self) -> Result<&'a str, LinkError> {
        self.run(
            |c| c.is_ascii_alphanumeric() || "!#$&+-.^_`|~*".contains(c),
            "a parameter name",
        )
    }

    /// A `ptoken` or a `quoted-string`, whose backslash escapes are undone.
    fn value(&mut self) -> Result<String, LinkError> {
        if !self.eat('"') {
            return self
                .run(
                    |c| c.is_ascii_alphanumeric() || "!#$%&'()*+-./:<=>?@[]^_`{|}~".contains(c),
                    "a value",
                )
                .map(str::to_owned);
        }
        let mut value = String::new();
        let mut chars = self.rest.char_indices();
        while let Some((at, c)) = chars.next() {
            match c {
                '"' => {
                    self.rest = &self.rest[at + 1..];
                    return Ok(value);
                }
                '\\' => match chars.next() {
                    Some((_, escaped)) => value.push(escaped),
                    None => break,
                },
                c => value.push(c),
            }
        }
        self.rest = "";
        Err(self.error("the closing `\"` of a value"))
    }
}

impl Link {
    /// Sets what the attribute `name` (lower case) with `value` says; `given` has those that may be given once.
    fn attribute(
        &mut self,
        name: &str,
        value: Option<&str>,
        given: &mut Vec<&'static str>,
    ) -> Result<(), LinkError> {
        let once = |attribute: &'static str, given: &mut Vec<&'static str>| {
            if given.contains(&attribute) {
                Err(LinkError::Repeated(attribute))
            } else {
                given.push(attribute);
                Ok(())
            }
        };
        match name {
            "anchor" => self.anchored = true,
            "rel" => {
                let types = relation_types("rel", value)?;
                if !given.contains(&"rel") {
                    given.push("rel");
                    self.rel = types;
                }
            }
            "rt" => {
                once("rt", given)?;
                self.rt = relation_types("rt", value)?;
            }
            "if" => {
                once("if", given)?;
                relation_types("if", value)?;
            }
            "sz" => {
                once("sz", given)?;
                cardinal("sz", value)?;
            }
            "ct" => {
                once("ct", given)?;
                let invalid = LinkError::Value {
                    attribute: "ct",
                    expected: "a content format code below 65536, or several separated by spaces",
                };
                let codes = value.ok_or_else(|| invalid.clone())?.split(' ');
                self.ct = codes
                    .map(|code| {
                        cardinal("ct", Some(code))?
                            .parse()
                            .map_err(|_| invalid.clone())
                    })
                    .collect::<Result<_, _>>()?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// The `relation-types` of `value`: one or more, separated by single spaces (RFC 6690 §2).
fn relation_types(attribute: &'static str, value: Option<&str>) -> Result<Vec<String>, LinkError> {
    let types: Vec<String> = value
        .map(|value| value.split(' ').map(str::to_owned).collect())
        .unwrap_or_default();
    if types.is_empty() || types.iter().any(String::is_empty) {
        return Err(LinkError::Value {
            attribute,
            expected: "one or more values separated by single spaces",
        });
    }
    Ok(types)
}

/// The `cardinal` of `value`, its digits: no sign, no leading zero (RFC 6690 §2).
fn cardinal<'a>(attribute: &'static str, value: Option<&'a str>) -> Result<&'a str, LinkError> {
    match value {
        Some(digits)
            if !digits.is_empty()
                && digits.bytes().all(|byte| byte.is_ascii_digit())
                && (digits.len() == 1 || !digits.starts_with('0')) =>
        {
            Ok(digits)
        }
        _ => Err(LinkError::Value {
            attribute,
            expected: "a number without a sign or a leading zero",
        }),
    }
}

/// `target` against `coap://{server}/.well-known/core` (RFC 3986 §5.2), as a path.
fn resolve(target: &str, server: SocketAddr) -> Result<String, &'static str> {
    fn split(rest: &str) -> (Option<&str>, &str) {
        let (authority, path) = rest.find('/').map_or((rest, ""), |at| rest.split_at(at));
        (Some(authority), path)
    }
    let (authority, reference) = match scheme(target) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("coap") => split(
            rest.strip_prefix("//")
                .ok_or("a coap URI without authority")?,
        ),
        Some(_) => return Err("not a coap URI"),
        None => target.strip_prefix("//").map_or((None, target), split),
    };
    if authority.is_some_and(|authority| !is_server(authority, server)) {
        return Err("not the server that sent the links, by IP address and port");
    }
    if reference.contains(['?', '#']) {
        return Err("a query or a fragment");
    }
    let path = if reference.starts_with('/') {
        reference.to_owned()
    } else if authority.is_some() {
        "/".to_owned()
    } else if reference.is_empty() {
        WELL_KNOWN.to_owned()
    } else {
        // The base path up to its last `/`, then the reference (RFC 3986 §5.2.3).
        format!("/.well-known/{reference}")
    };
    Ok(without_dots(&path))
}

/// A path segment with its percent-encodings converted to the bytes they stand for (RFC 7252 §6.4).
fn decode(segment: &[u8]) -> Result<Box<[u8]>, &'static str> {
    let mut bytes = Vec::with_capacity(segment.len());
    let mut rest = segment;
    while let Some((&byte, after)) = rest.split_first() {
        rest = after;
        if byte != b'%' {
            bytes.push(byte);
            continue;
        }
        let [high, low, after @ ..] = rest else {
            return Err("a percent-encoding that is not two hexadecimal digits");
        };
        let digit = |digit: &u8| char::from(*digit).to_digit(16);
        let (Some(high), Some(low)) = (digit(high), digit(low)) else {
            return Err("a percent-encoding that is not two hexadecimal digits");
        };
        bytes.push(u8::try_from(high << 4 | low).expect("two hexadecimal digits fit a byte"));
        rest = after;
    }
    if bytes == b"." || bytes == b".." {
        return Err("a dot segment");
    }
    Ok(bytes.into())
}

/// The scheme of the URI reference `target` and what follows its `:`, if it has one (RFC 3986 §3.1).
fn scheme(target: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = target.split_once(':')?;
    let mut chars = scheme.chars();
    (chars.next()?.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)))
    .then_some((scheme, rest))
}

/// Whether `authority` is the IP address and port of `server`, the port 5683 when it has none.
fn is_server(authority: &str, server: SocketAddr) -> bool {
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, port)) => match port.strip_prefix(':') {
                Some(port) => (host, Some(port)),
                None => return false,
            },
            None => return false,
        },
        None => authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port))),
    };
    let port = match port.map(str::parse) {
        None => COAP_PORT,
        Some(Ok(port)) => port,
        Some(Err(_)) => return false,
    };
    port == server.port() && host.parse::<IpAddr>().is_ok_and(|ip| ip == server.ip())
}

/// `path`, which starts with `/`, without its `.` and `..` segments (RFC 3986 §5.2.4); empty segments stay.
fn without_dots(path: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut last = "";
    for segment in path.split('/').skip(1) {
        last = segment;
        match segment {
            "." => {}
            ".." => {
                kept.pop();
            }
            segment => kept.push(segment),
        }
    }
    // A path ending in a dot segment ends in `/`.
    if matches!(last, "." | "..") {
        kept.push("");
    }
    format!("/{}", kept.join("/"))
}
