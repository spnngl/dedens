//! Zone files, the master files of RFC 1035 §5: entries of records and directives.

use super::{Fields, Head, Lexer, TextError, TextErrorKind, Token};
use crate::codes::Class;
use crate::name::Name;
use crate::rdata::RData;
use crate::record::{DecodedRecord, Record, Ttl};

/// What a zone file holds, entry by entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Entry {
    /// A resource record, its owner, TTL and class filled in from the defaults, and why its RDATA, written
    /// `\# length hex`, was kept opaque if it is invalid for its type (D9); the offset of that reason is in the
    /// RDATA.
    Record(DecodedRecord<'static>),
    /// A `$INCLUDE`: the caller reads `file` and passes its text to [`ZoneReader::include`] with `origin`.
    Include {
        /// The file name, as written once quotes and escapes are decoded.
        file: String,
        /// The origin of the included file: the name given after the file, else the current origin.
        origin: Option<Name<'static>>,
    },
}

/// TTL and class of a record that leaves them out.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Defaults {
    /// The last `$TTL` (RFC 2308 §4).
    ttl: Option<Ttl>,
    /// The last TTL written in a record (RFC 1035 §5.1), used without `$TTL`.
    last_ttl: Option<Ttl>,
    /// The last class written in a record.
    last_class: Option<Class>,
}

impl Defaults {
    /// Reads the record after its owner, filling in an omitted TTL or class, and remembers the explicit ones.
    pub(crate) fn record(
        &mut self,
        owner: Name<'static>,
        f: &mut Fields<'_, '_>,
    ) -> Result<DecodedRecord<'static>, TextError> {
        let head = Head::read(f)?;
        let (line, column) = head.at;
        let explicit = head.ttl;
        let ttl = explicit.or(self.ttl).or(self.last_ttl).ok_or(TextError {
            line,
            column,
            kind: TextErrorKind::NoTtl,
        })?;
        let class = head.class.or(self.last_class).unwrap_or(Class::IN);
        let (data, invalid_rdata) = RData::from_text(head.rtype, f)?;
        f.finish()?;
        self.last_ttl = explicit.or(self.last_ttl);
        self.last_class = head.class.or(self.last_class);
        Ok(DecodedRecord {
            record: Record::new(owner, class, ttl, data),
            invalid_rdata,
        })
    }
}

/// Reads the entries of a zone file (RFC 1035 §5.1) with `$ORIGIN`, `$INCLUDE` and `$TTL` (RFC 2308 §4).
///
/// An omitted owner is the last one; an omitted TTL is the last `$TTL`, else the last TTL written, else an error;
/// an omitted class is the last one written, else IN. `$INCLUDE` is handed to the caller, which reads the file.
/// The reader stops at the first error.
#[derive(Debug, Clone)]
pub struct ZoneReader<'t> {
    lexer: Lexer<'t>,
    origin: Option<Name<'static>>,
    owner: Option<Name<'static>>,
    defaults: Defaults,
    failed: bool,
}

impl<'t> ZoneReader<'t> {
    /// A reader of `text`, relative names completed with `origin`; without one, a relative name is an error until
    /// a `$ORIGIN`.
    #[must_use]
    pub fn new(text: &'t [u8], origin: Option<Name<'static>>) -> Self {
        Self {
            lexer: Lexer::new(text),
            origin,
            owner: None,
            defaults: Defaults::default(),
            failed: false,
        }
    }

    /// The same reader with a default TTL, as if the text started with `$TTL secs`; for files without TTLs such
    /// as the example of RFC 1035 §5.3.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Ttl) -> Self {
        self.defaults.ttl = Some(ttl);
        self
    }

    /// A reader of the text of a `$INCLUDE`d file: same TTL and class defaults, its own origin, no owner yet.
    /// Nothing it reads changes this reader (RFC 1035 §5.1).
    #[must_use]
    pub fn include<'u>(&self, text: &'u [u8], origin: Option<Name<'static>>) -> ZoneReader<'u> {
        ZoneReader {
            defaults: self.defaults,
            ..ZoneReader::new(text, origin)
        }
    }

    /// The current origin.
    #[must_use]
    pub const fn origin(&self) -> Option<&Name<'static>> {
        self.origin.as_ref()
    }

    fn entry(&mut self) -> Result<Option<Entry>, TextError> {
        loop {
            let Some(blank) = self.lexer.entry()? else {
                return Ok(None);
            };
            let mut f = Fields::new(&mut self.lexer, self.origin.as_ref());
            let owner = if blank {
                match self.owner.clone() {
                    Some(owner) => owner,
                    None => return Err(f.next("owner name")?.error(TextErrorKind::NoOwner)),
                }
            } else {
                let first = f.next("owner name")?;
                if first.raw.first() == Some(&b'$') {
                    match directive(first, &mut f)? {
                        Directive::Origin(origin) => self.origin = Some(origin),
                        Directive::Ttl(ttl) => self.defaults.ttl = Some(ttl),
                        Directive::Include { file, origin } => {
                            let origin = origin.or_else(|| self.origin.clone());
                            return Ok(Some(Entry::Include { file, origin }));
                        }
                    }
                    continue;
                }
                let name = Name::from_text(first.raw, self.origin.as_ref())
                    .map_err(|kind| first.error(kind))?;
                self.owner = Some(name.clone());
                name
            };
            return self
                .defaults
                .record(owner, &mut f)
                .map(|r| Some(Entry::Record(r)));
        }
    }
}

impl Iterator for ZoneReader<'_> {
    type Item = Result<Entry, TextError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let entry = self.entry();
        self.failed = entry.is_err();
        entry.transpose()
    }
}

impl core::iter::FusedIterator for ZoneReader<'_> {}

enum Directive {
    Origin(Name<'static>),
    Ttl(Ttl),
    Include {
        file: String,
        origin: Option<Name<'static>>,
    },
}

/// Reads the directive named by `first`; relative names in it are completed with the current origin.
fn directive(first: Token<'_>, f: &mut Fields<'_, '_>) -> Result<Directive, TextError> {
    let is = |name: &[u8]| first.raw.eq_ignore_ascii_case(name);
    let directive = if is(b"$ORIGIN") {
        Directive::Origin(f.name("$ORIGIN name")?)
    } else if is(b"$TTL") {
        let token = f.next("$TTL value")?;
        let ttl = super::seconds(token.raw)
            .and_then(Ttl::new)
            .ok_or(token.error(TextErrorKind::Invalid("TTL")))?;
        Directive::Ttl(ttl)
    } else if is(b"$INCLUDE") {
        let token = f.next("$INCLUDE file name")?;
        let file = super::unescape(token.raw)
            .map_err(|kind| token.error(kind))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|_| token.error(TextErrorKind::Invalid("file name, not UTF-8")))
            })?;
        let origin = match f.peek()? {
            Some(_) => Some(f.name("$INCLUDE origin")?),
            None => None,
        };
        Directive::Include { file, origin }
    } else {
        return Err(first.error(TextErrorKind::UnknownDirective));
    };
    f.finish()?;
    Ok(directive)
}
