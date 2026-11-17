//! IANA's `root-anchors.xml` (RFC 9718 §2): its `KeyDigest` entries valid at a time, as DS records.
//!
//! A reader of this one schema, not of XML (D127): elements, attributes, text, comments and the XML declaration.
//! A DOCTYPE, a CDATA section or an entity reference is refused, as IANA's file holds none. Unknown elements and
//! attributes are skipped, so that a schema grown by a later RFC still reads.

use std::collections::{HashMap, HashSet};

use data_encoding::{BASE64, HEXUPPER_PERMISSIVE};
use dedens_proto::rdata::Ds;
use dedens_proto::{DigestType, Name, SecAlgorithm};
use x509_cert::der::DateTime;

use super::{Anchor, TrustAnchors};
use crate::crypto::{ds_digest, key_tag};

/// Why `root-anchors.xml` is refused (RFC 9718 §2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorXmlError {
    /// Not the XML this reader reads.
    #[error("byte {at}: {what}")]
    Syntax {
        /// The offset in the file where reading stopped.
        at: usize,
        /// What is there.
        what: &'static str,
    },
    /// Well-formed, but not the schema of RFC 9718 §2.1, or a value in it is not valid; says which.
    #[error("{0}")]
    Invalid(&'static str),
    /// No `KeyDigest` is valid at the time asked (RFC 9718 §2.2): each expired, is not valid yet, or does not
    /// match the DNSKEY it carries (§4.1.2).
    #[error("no KeyDigest is valid now")]
    NoneValid,
}

/// The anchors of the `KeyDigest` entries of `xml` valid at `now`, in seconds since 1970 (RFC 9718 §2.2,
/// §4.1.1): from `validFrom` on and before `validUntil`. An entry carrying `PublicKey` and `Flags` whose digest
/// or key tag does not match that DNSKEY is not used (§4.1.2).
pub(super) fn read(xml: &[u8], now: u64) -> Result<TrustAnchors, AnchorXmlError> {
    let text = str::from_utf8(xml).map_err(|error| AnchorXmlError::Syntax {
        at: error.valid_up_to(),
        what: "not UTF-8",
    })?;
    let mut lexer = Lexer {
        text,
        at: 0,
        pending_end: None,
    };
    let mut open: Vec<&str> = Vec::new();
    let mut seen_root = false;
    let mut zone = None;
    let mut entries: Vec<Entry> = Vec::new();
    let mut chars = String::new();
    while let Some(event) = lexer.next()? {
        match event {
            Event::Start { name, attributes } => {
                if open.is_empty() {
                    if seen_root {
                        return Err(lexer.error("a second root element"));
                    }
                    if name != "TrustAnchor" {
                        return Err(AnchorXmlError::Invalid(
                            "the root element is not TrustAnchor",
                        ));
                    }
                    seen_root = true;
                }
                open.push(name);
                if open == ["TrustAnchor", "KeyDigest"] {
                    let entry = Entry::new(attributes).map_err(|what| lexer.error(what))?;
                    entries.push(entry);
                }
                chars.clear();
            }
            Event::Text(text) => {
                if open.is_empty() && !text.trim_matches(is_space).is_empty() {
                    return Err(lexer.error("text outside the root element"));
                }
                chars.push_str(text);
            }
            Event::End(name) => {
                if open.last() != Some(&name) {
                    return Err(lexer.error("an end tag that closes no open element"));
                }
                let text = std::mem::take(&mut chars);
                match (open.as_slice(), entries.last_mut()) {
                    (["TrustAnchor", "Zone"], _) => set(&mut zone, text)?,
                    (["TrustAnchor", "KeyDigest", field], Some(entry)) => entry.set(field, text)?,
                    _ => {}
                }
                open.pop();
            }
        }
    }
    if !open.is_empty() {
        return Err(lexer.error("an element not closed"));
    }
    if !seen_root {
        return Err(AnchorXmlError::Invalid("no TrustAnchor element"));
    }
    let zone: Name<'static> = zone
        .ok_or(AnchorXmlError::Invalid("no Zone element"))?
        .trim_matches(is_space)
        .parse()
        .map_err(|_| AnchorXmlError::Invalid("a Zone that is not a domain name"))?;
    let mut ds = Vec::new();
    for entry in &entries {
        if let Some(record) = entry.ds(&zone, now)? {
            ds.push(record);
        }
    }
    if ds.is_empty() {
        return Err(AnchorXmlError::NoneValid);
    }
    Ok(TrustAnchors {
        zones: HashMap::from([(
            zone,
            Anchor {
                ds,
                dnskeys: Vec::new(),
            },
        )]),
        negative: HashSet::new(),
    })
}

/// Sets an element's text once: the schema has each element at most once where this reader looks.
fn set(field: &mut Option<String>, text: String) -> Result<(), AnchorXmlError> {
    match field.replace(text) {
        Some(_) => Err(AnchorXmlError::Invalid("an element twice")),
        None => Ok(()),
    }
}

/// The white space of XML (XML 1.0 §2.3), which may surround values and split a `Digest` or a `PublicKey`.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// One `KeyDigest` as written, each value read only when the entry is used.
#[derive(Default)]
struct Entry {
    valid_from: Option<String>,
    valid_until: Option<String>,
    key_tag: Option<String>,
    algorithm: Option<String>,
    digest_type: Option<String>,
    digest: Option<String>,
    public_key: Option<String>,
    flags: Option<String>,
}

impl Entry {
    /// An entry with the `validFrom` and `validUntil` of the attributes of its start tag.
    fn new(attributes: &str) -> Result<Self, &'static str> {
        let mut entry = Self::default();
        let mut rest = attributes.trim_start_matches(is_space);
        while !rest.is_empty() {
            let (name, after) = rest.split_once('=').ok_or("an attribute without a value")?;
            let after = after.trim_start_matches(is_space);
            let quote = after.chars().next().filter(|c| matches!(c, '"' | '\''));
            let quote = quote.ok_or("an attribute value not quoted")?;
            let value = after.get(1..).unwrap_or_default();
            let (value, after) = value
                .split_once(quote)
                .ok_or("an attribute value not ended")?;
            if value.contains(['&', '<']) {
                return Err("an entity reference or a '<' in an attribute value");
            }
            let field = match name.trim_end_matches(is_space) {
                "validFrom" => Some(&mut entry.valid_from),
                "validUntil" => Some(&mut entry.valid_until),
                _ => None,
            };
            if let Some(field) = field
                && field.replace(value.to_owned()).is_some()
            {
                return Err("an attribute twice");
            }
            let next = after.trim_start_matches(is_space);
            if next.len() == after.len() && !next.is_empty() {
                return Err("attributes not separated by white space");
            }
            rest = next;
        }
        Ok(entry)
    }

    /// Sets the text of a child element; unknown ones are skipped.
    fn set(&mut self, element: &str, text: String) -> Result<(), AnchorXmlError> {
        let field = match element {
            "KeyTag" => &mut self.key_tag,
            "Algorithm" => &mut self.algorithm,
            "DigestType" => &mut self.digest_type,
            "Digest" => &mut self.digest,
            "PublicKey" => &mut self.public_key,
            "Flags" => &mut self.flags,
            _ => return Ok(()),
        };
        set(field, text)
    }

    /// The DS record of the entry if it is valid at `now`, `None` if not. Every value is read, so that an entry
    /// out of its time is refused all the same when it is not valid.
    fn ds(&self, zone: &Name<'_>, now: u64) -> Result<Option<Ds<'static>>, AnchorXmlError> {
        let valid_from = date_time(required(
            self.valid_from.as_deref(),
            "a KeyDigest without validFrom",
        )?)?;
        let valid_until = self.valid_until.as_deref().map(date_time).transpose()?;
        let tag: u16 = number(self.key_tag.as_deref(), "a KeyTag that is not 0 to 65535")?;
        let algorithm = SecAlgorithm(number(
            self.algorithm.as_deref(),
            "an Algorithm that is not 0 to 255",
        )?);
        let digest_type = DigestType(number(
            self.digest_type.as_deref(),
            "a DigestType that is not 0 to 255",
        )?);
        let digest = compact(required(
            self.digest.as_deref(),
            "a KeyDigest without Digest",
        )?);
        let digest = HEXUPPER_PERMISSIVE
            .decode(digest.as_bytes())
            .map_err(|_| AnchorXmlError::Invalid("a Digest that is not hexadecimal"))?;
        let ds = Ds::new(tag, algorithm, digest_type, &digest)
            .map_err(|_| AnchorXmlError::Invalid("a KeyDigest that is not a valid DS record"))?
            .into_owned();
        let dnskey = match (self.public_key.as_deref(), self.flags.as_deref()) {
            (None, None) => None,
            (Some(key), Some(flags)) => {
                let flags: u16 = number(Some(flags), "Flags that are not 0 to 65535")?;
                let key = BASE64
                    .decode(compact(key).as_bytes())
                    .map_err(|_| AnchorXmlError::Invalid("a PublicKey that is not base64"))?;
                let mut rdata = Vec::from(flags.to_be_bytes());
                rdata.extend([3, algorithm.0]);
                rdata.extend(key);
                Some(rdata)
            }
            _ => {
                return Err(AnchorXmlError::Invalid(
                    "a PublicKey without Flags or Flags without it",
                ));
            }
        };
        if now < valid_from || valid_until.is_some_and(|until| now >= until) {
            return Ok(None);
        }
        let matches = dnskey.is_none_or(|rdata| {
            key_tag(&rdata) == tag
                && ds_digest(digest_type, zone, &rdata).is_ok_and(|d| d.as_ref() == digest)
        });
        Ok(matches.then_some(ds))
    }
}

fn required<'a>(text: Option<&'a str>, missing: &'static str) -> Result<&'a str, AnchorXmlError> {
    text.ok_or(AnchorXmlError::Invalid(missing))
}

/// A decimal number of the type asked, without the sign Rust's parser accepts; `invalid` when absent or not one.
fn number<T: core::str::FromStr>(
    text: Option<&str>,
    invalid: &'static str,
) -> Result<T, AnchorXmlError> {
    text.map(|text| text.trim_matches(is_space))
        .filter(|text| text.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or(AnchorXmlError::Invalid(invalid))
}

/// The text without its white space, which a long `Digest` or `PublicKey` may hold (RFC 9718 §2.1.2).
fn compact(text: &str) -> String {
    text.chars().filter(|&c| !is_space(c)).collect()
}

/// Seconds since 1970 of an XML Schema `dateTime` (RFC 9718 §2.1.2) with a time zone, `Z` or `±hh:mm`, and
/// without fractions of a second, as IANA writes them.
fn date_time(text: &str) -> Result<u64, AnchorXmlError> {
    const INVALID: AnchorXmlError =
        AnchorXmlError::Invalid("a date that is not YYYY-MM-DDThh:mm:ss and a time zone");
    let text = text.trim_matches(is_space);
    let (local, offset) = if let Some(local) = text.strip_suffix('Z') {
        (local, 0_i64)
    } else {
        let (local, zone) = text
            .split_at_checked(text.len().saturating_sub(6))
            .ok_or(INVALID)?;
        let sign = match zone.get(..1) {
            Some("+") => 1,
            Some("-") => -1,
            _ => return Err(INVALID),
        };
        let hours: i64 = digits(zone, 1..3).ok_or(INVALID)?;
        let minutes: i64 = digits(zone, 4..6).ok_or(INVALID)?;
        if zone.get(3..4) != Some(":") || hours > 14 || minutes > 59 {
            return Err(INVALID);
        }
        (local, sign * (hours * 3600 + minutes * 60))
    };
    let separators = [(4, "-"), (7, "-"), (10, "T"), (13, ":"), (16, ":")];
    if local.len() != 19
        || separators
            .iter()
            .any(|&(at, s)| local.get(at..=at) != Some(s))
    {
        return Err(INVALID);
    }
    let field = |range| digits::<u8>(local, range).ok_or(INVALID);
    let time = DateTime::new(
        digits(local, 0..4).ok_or(INVALID)?,
        field(5..7)?,
        field(8..10)?,
        field(11..13)?,
        field(14..16)?,
        field(17..19)?,
    )
    .map_err(|_| INVALID)?;
    time.unix_duration()
        .as_secs()
        .checked_add_signed(-offset)
        .ok_or(INVALID)
}

/// The decimal digits of `text` at `range`, all digits.
fn digits<T: core::str::FromStr>(text: &str, range: core::ops::Range<usize>) -> Option<T> {
    text.get(range)
        .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

/// What the lexer reads.
enum Event<'a> {
    /// A start tag, or an empty-element tag (then an [`Event::End`] follows).
    Start { name: &'a str, attributes: &'a str },
    /// An end tag.
    End(&'a str),
    /// Character data between tags.
    Text(&'a str),
}

/// Splits the file into tags and text, skipping comments and processing instructions.
struct Lexer<'a> {
    text: &'a str,
    at: usize,
    /// The name of the empty-element tag just read, whose end comes next.
    pending_end: Option<&'a str>,
}

impl<'a> Lexer<'a> {
    fn error(&self, what: &'static str) -> AnchorXmlError {
        AnchorXmlError::Syntax { at: self.at, what }
    }

    /// The text from `at` up to `end`, which then follows; `missing` if `end` is not there.
    fn until(
        &mut self,
        skip: usize,
        end: &str,
        missing: &'static str,
    ) -> Result<&'a str, AnchorXmlError> {
        let start = self.at + skip;
        let rest = self.text.get(start..).unwrap_or_default();
        let length = rest.find(end).ok_or_else(|| self.error(missing))?;
        self.at = start + length + end.len();
        Ok(rest.get(..length).unwrap_or_default())
    }

    fn next(&mut self) -> Result<Option<Event<'a>>, AnchorXmlError> {
        if let Some(name) = self.pending_end.take() {
            return Ok(Some(Event::End(name)));
        }
        loop {
            let rest = self.text.get(self.at..).unwrap_or_default();
            if rest.is_empty() {
                return Ok(None);
            }
            if rest.starts_with("<!--") {
                self.until(4, "-->", "a comment not ended")?;
            } else if rest.starts_with("<?") {
                self.until(2, "?>", "a processing instruction not ended")?;
            } else if rest.starts_with("<!") {
                return Err(self.error("a DOCTYPE or a CDATA section"));
            } else if rest.starts_with("</") {
                let name = self.until(2, ">", "an end tag not ended")?;
                return Ok(Some(Event::End(name.trim_end_matches(is_space))));
            } else if rest.starts_with('<') {
                return self.start().map(Some);
            } else {
                let length = rest.find('<').unwrap_or(rest.len());
                let text = rest.get(..length).unwrap_or_default();
                if text.contains('&') {
                    return Err(self.error("an entity reference"));
                }
                self.at += length;
                return Ok(Some(Event::Text(text)));
            }
        }
    }

    /// A start tag or an empty-element tag; a `>` may be in a quoted attribute value.
    fn start(&mut self) -> Result<Event<'a>, AnchorXmlError> {
        let rest = self.text.get(self.at + 1..).unwrap_or_default();
        let mut quote = None;
        let length = rest
            .char_indices()
            .find(|&(_, c)| match quote {
                Some(q) => {
                    if c == q {
                        quote = None;
                    }
                    false
                }
                None if matches!(c, '"' | '\'') => {
                    quote = Some(c);
                    false
                }
                None => c == '>',
            })
            .map(|(at, _)| at)
            .ok_or_else(|| self.error("a start tag not ended"))?;
        let tag = rest.get(..length).unwrap_or_default();
        let (tag, empty) = match tag.strip_suffix('/') {
            Some(tag) => (tag, true),
            None => (tag, false),
        };
        let (name, attributes) = tag.split_at(tag.find(is_space).unwrap_or(tag.len()));
        if name.is_empty() {
            return Err(self.error("a tag without a name"));
        }
        self.at += 1 + length + 1;
        if empty {
            self.pending_end = Some(name);
        }
        Ok(Event::Start { name, attributes })
    }
}
