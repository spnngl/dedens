//! SVCB and HTTPS: service binding (RFC 9460), with the `dohpath` key of RFC 9461 and the `docpath` key of RFC 9953.
//!
//! The wire form is `priority, target (never compressed), (key, length, value)*` with keys strictly increasing
//! (RFC 9460 §2.2). [`SvcParams`] only holds a list that is valid and consistent (RFC 9460 §2.4), so a decoded
//! record can be encoded again and a built one is never rejected by a peer for its parameters.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use std::borrow::Cow;

use super::MAX_RDATA_LEN;
use crate::codes::code_type;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::Name;
use crate::text::encoding::{Base64, decode_base64};
use crate::text::{self, Fields, Quoted, TextError, TextErrorKind};
use crate::wire::{Reader, Writer};

/// Bytes of `SvcPriority` before the target.
const PRIORITY_LEN: usize = 2;

code_type! {
    /// `SvcParamKey` (RFC 9460 §14.3.2).
    SvcParamKey(u16), "key";
    /// Keys that must be understood for the record to work (RFC 9460 §8).
    MANDATORY = 0, "mandatory";
    /// Supported application protocols (RFC 9460 §7.1).
    ALPN = 1, "alpn";
    /// No default protocol set (RFC 9460 §7.1).
    NO_DEFAULT_ALPN = 2, "no-default-alpn";
    /// Alternative port (RFC 9460 §7.2).
    PORT = 3, "port";
    /// IPv4 address hints (RFC 9460 §7.3).
    IPV4HINT = 4, "ipv4hint";
    /// Encrypted `ClientHello` configuration (RFC 9460 §14.3.2).
    ECH = 5, "ech";
    /// IPv6 address hints (RFC 9460 §7.3).
    IPV6HINT = 6, "ipv6hint";
    /// URI template path of a `DoH` server (RFC 9461 §5).
    DOHPATH = 7, "dohpath";
    /// URI path of a `DoC` server, as segments (RFC 9953 §3.2).
    DOCPATH = 10, "docpath";
}

impl SvcParamKey {
    /// Reserved, never valid on the wire (RFC 9460 §14.3.2).
    const INVALID: Self = Self(65535);

    /// Reads a key as RFC 9460 §2.1 writes it: a registered name in lowercase, or `key` and the number without
    /// leading zeros. Stricter than `FromStr`, which takes any case like the other codes.
    fn from_text(text: &[u8]) -> Option<Self> {
        if let Some(digits) = text.strip_prefix(b"key") {
            let canonical = digits.first() != Some(&b'0') || digits == b"0";
            return canonical.then(|| text::number(digits).map(Self)).flatten();
        }
        (0..=Self::DOCPATH.0)
            .map(Self)
            .find(|key| key.mnemonic().is_some_and(|m| m.as_bytes() == text))
    }

    /// Keys 0 to 7 and 10 have a typed [`SvcParam`] variant; they cannot be carried as [`SvcParam::Unknown`].
    const fn is_known(self) -> bool {
        self.0 <= Self::DOHPATH.0 || self.0 == Self::DOCPATH.0
    }
}

/// One service parameter, parsed by key (RFC 9460 §7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SvcParam {
    /// Keys, besides itself, that a client must understand (RFC 9460 §8).
    Mandatory(Vec<SvcParamKey>),
    /// ALPN protocol identifiers, 1 to 255 bytes each (RFC 9460 §7.1).
    Alpn(Vec<Box<[u8]>>),
    /// The default protocol set does not apply (RFC 9460 §7.1).
    NoDefaultAlpn,
    /// Port of the endpoint (RFC 9460 §7.2).
    Port(u16),
    /// IPv4 address hints (RFC 9460 §7.3).
    Ipv4Hint(Vec<Ipv4Addr>),
    /// Encrypted `ClientHello` configuration, opaque here.
    Ech(Box<[u8]>),
    /// IPv6 address hints (RFC 9460 §7.3).
    Ipv6Hint(Vec<Ipv6Addr>),
    /// URI template path of a `DoH` server (RFC 9461 §5).
    DohPath(String),
    /// The path segments of a `DoC` server, each 0 to 255 bytes; none is the root path (RFC 9953 §3.2). Laid out
    /// as `alpn` is, but a segment may be empty.
    DocPath(Vec<Box<[u8]>>),
    /// A key without a typed variant; its key is 8, 9 or above 10 (RFC 9460 §2.2).
    Unknown {
        /// The key.
        key: SvcParamKey,
        /// The value, not interpreted.
        value: Box<[u8]>,
    },
}

impl SvcParam {
    /// The key of this parameter.
    #[must_use]
    pub const fn key(&self) -> SvcParamKey {
        match self {
            Self::Mandatory(_) => SvcParamKey::MANDATORY,
            Self::Alpn(_) => SvcParamKey::ALPN,
            Self::NoDefaultAlpn => SvcParamKey::NO_DEFAULT_ALPN,
            Self::Port(_) => SvcParamKey::PORT,
            Self::Ipv4Hint(_) => SvcParamKey::IPV4HINT,
            Self::Ech(_) => SvcParamKey::ECH,
            Self::Ipv6Hint(_) => SvcParamKey::IPV6HINT,
            Self::DohPath(_) => SvcParamKey::DOHPATH,
            Self::DocPath(_) => SvcParamKey::DOCPATH,
            Self::Unknown { key, .. } => *key,
        }
    }

    /// Parses a value [`check`] accepted; `None` only if it did not.
    fn parse(key: SvcParamKey, value: &[u8]) -> Option<Self> {
        Some(match key {
            SvcParamKey::MANDATORY => Self::Mandatory(
                value
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|k| SvcParamKey(u16::from_be_bytes(*k)))
                    .collect(),
            ),
            SvcParamKey::ALPN => Self::Alpn(length_prefixed(value)?),
            SvcParamKey::NO_DEFAULT_ALPN => Self::NoDefaultAlpn,
            SvcParamKey::PORT => Self::Port(u16::from_be_bytes(value.try_into().ok()?)),
            SvcParamKey::IPV4HINT => Self::Ipv4Hint(
                value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|a| Ipv4Addr::from(*a))
                    .collect(),
            ),
            SvcParamKey::ECH => Self::Ech(value.into()),
            SvcParamKey::IPV6HINT => Self::Ipv6Hint(
                value
                    .as_chunks::<16>()
                    .0
                    .iter()
                    .map(|a| Ipv6Addr::from(*a))
                    .collect(),
            ),
            SvcParamKey::DOHPATH => Self::DohPath(str::from_utf8(value).ok()?.into()),
            SvcParamKey::DOCPATH => Self::DocPath(length_prefixed(value)?),
            _ => Self::Unknown {
                key,
                value: value.into(),
            },
        })
    }

    /// Appends the value, without key and length.
    fn encode_value(&self, out: &mut Vec<u8>) -> Result<(), SvcParamsError> {
        match self {
            Self::Mandatory(keys) => keys.iter().for_each(|k| out.extend(k.0.to_be_bytes())),
            Self::Alpn(ids) | Self::DocPath(ids) => {
                for id in ids {
                    let len = u8::try_from(id.len()).map_err(|_| SvcParamsError::Malformed)?;
                    out.push(len);
                    out.extend_from_slice(id);
                }
            }
            Self::NoDefaultAlpn => {}
            Self::Port(port) => out.extend(port.to_be_bytes()),
            Self::Ipv4Hint(hints) => hints.iter().for_each(|a| out.extend(a.octets())),
            Self::Ech(config) => out.extend_from_slice(config),
            Self::Ipv6Hint(hints) => hints.iter().for_each(|a| out.extend(a.octets())),
            Self::DohPath(path) => out.extend_from_slice(path.as_bytes()),
            Self::Unknown { value, .. } => out.extend_from_slice(value),
        }
        Ok(())
    }
}

/// The items of a value laid out as `alpn` is: each a length octet and that many bytes, exactly filling `value`.
fn length_prefixed(value: &[u8]) -> Option<Vec<Box<[u8]>>> {
    let mut items = Vec::new();
    let mut rest = value;
    while let Some((&len, tail)) = rest.split_first() {
        let (item, tail) = tail.split_at_checked(usize::from(len))?;
        items.push(item.into());
        rest = tail;
    }
    Some(items)
}

/// A parameter list that breaks RFC 9460 (§2.2, §2.4.3, §7, §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SvcParamsError {
    /// A parameter appears twice.
    #[error("service parameter {0} appears more than once")]
    Duplicate(SvcParamKey),
    /// `mandatory` lists a key twice.
    #[error("mandatory lists key {0} more than once")]
    MandatoryTwice(SvcParamKey),
    /// A list-valued parameter or `ech` has no element, or an ALPN identifier is empty; `domain` refuses an empty
    /// `ech=` too.
    #[error("service parameter {0} has an empty value")]
    Empty(SvcParamKey),
    /// `mandatory` lists a key that is not in the parameters, or itself.
    #[error("mandatory lists key {0}, which is missing or not allowed")]
    BadMandatory(SvcParamKey),
    /// An unknown-key parameter uses a key that has a typed variant, or the reserved key 65535.
    #[error("key {0} cannot be carried as an unknown parameter")]
    ReservedKey(SvcParamKey),
    /// `no-default-alpn` without `alpn`, which would leave no protocol to connect with (RFC 9460 §7.1.1).
    #[error("no-default-alpn without alpn")]
    NoDefaultAlpnWithoutAlpn,
    /// Keys out of order, a value of the wrong length or not UTF-8, an ALPN identifier over 255 bytes, a value
    /// over 65535 bytes.
    #[error("malformed service parameters")]
    Malformed,
    /// Priority, target and parameters over the 65535 bytes of an RDATA.
    #[error("SVCB RDATA longer than 65535 bytes")]
    TooLong,
}

/// The parameters of a SVCB or HTTPS record, in wire form: sorted by key, each key once, internally consistent.
///
/// Borrowed from the message they were decoded from, or owned; [`SvcParams::iter`] parses them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SvcParams<'a>(Cow<'a, [u8]>);

impl SvcParams<'_> {
    /// Parameters from `params` in any order; sorts them by key, and the keys of `mandatory`.
    ///
    /// # Errors
    ///
    /// [`SvcParamsError`] when a key repeats, a value that needs elements has none, `mandatory` lists itself or a
    /// missing key, `no-default-alpn` comes without `alpn`, an unknown parameter uses key 0 to 7 or 65535, a
    /// value is too long for the wire, or the list would not fit an RDATA even with the root as target.
    pub fn new(mut params: Vec<SvcParam>) -> Result<SvcParams<'static>, SvcParamsError> {
        params.sort_by_key(SvcParam::key);
        let mut wire = Vec::new();
        for param in &mut params {
            match param {
                SvcParam::Mandatory(keys) => keys.sort_unstable(),
                SvcParam::Unknown { key, .. } if key.is_known() || *key == SvcParamKey::INVALID => {
                    return Err(SvcParamsError::ReservedKey(*key));
                }
                _ => {}
            }
            wire.extend(param.key().0.to_be_bytes());
            let at = wire.len();
            wire.extend([0, 0]);
            param.encode_value(&mut wire)?;
            let len = u16::try_from(wire.len() - at - 2).map_err(|_| SvcParamsError::Malformed)?;
            if let Some(dst) = wire.get_mut(at..at + 2) {
                dst.copy_from_slice(&len.to_be_bytes());
            }
        }
        if wire.len() > MAX_RDATA_LEN - PRIORITY_LEN - 1 {
            return Err(SvcParamsError::TooLong);
        }
        check(&wire)?;
        Ok(SvcParams(Cow::Owned(wire)))
    }

    /// The parameters, by increasing key.
    #[must_use]
    pub fn iter(&self) -> Params<'_> {
        Params(&self.0)
    }

    /// The parameter with `key`, if present.
    #[must_use]
    pub fn get(&self, key: SvcParamKey) -> Option<SvcParam> {
        self.iter().find(|p| p.key() == key)
    }

    /// Whether there is no parameter.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The same parameters, owning their bytes.
    #[must_use]
    pub fn into_owned(self) -> SvcParams<'static> {
        SvcParams(Cow::Owned(self.0.into_owned()))
    }
}

impl<'p> IntoIterator for &'p SvcParams<'_> {
    type Item = SvcParam;
    type IntoIter = Params<'p>;

    fn into_iter(self) -> Params<'p> {
        self.iter()
    }
}

/// Iterator over [`SvcParams`], parsing each parameter.
#[derive(Debug, Clone)]
pub struct Params<'p>(&'p [u8]);

impl Iterator for Params<'_> {
    type Item = SvcParam;

    fn next(&mut self) -> Option<SvcParam> {
        let (key, value, rest) = split_param(self.0)?;
        self.0 = rest;
        SvcParam::parse(key, value)
    }
}

/// The key and value of the first parameter of `wire`, and the bytes after it.
fn split_param(wire: &[u8]) -> Option<(SvcParamKey, &[u8], &[u8])> {
    let ([k0, k1, l0, l1], rest) = wire.split_first_chunk::<4>()?;
    let (value, rest) = rest.split_at_checked(usize::from(u16::from_be_bytes([*l0, *l1])))?;
    Some((SvcParamKey(u16::from_be_bytes([*k0, *k1])), value, rest))
}

/// Checks a parameter list in wire form against RFC 9460 (§2.2, §7, §8), without allocating.
fn check(wire: &[u8]) -> Result<(), SvcParamsError> {
    use SvcParamsError::{
        BadMandatory, Duplicate, Empty, Malformed, MandatoryTwice, NoDefaultAlpnWithoutAlpn,
    };
    let mut rest = wire;
    let mut previous = None;
    let mut mandatory: &[[u8; 2]] = &[];
    let (mut alpn, mut no_default_alpn) = (false, false);
    while !rest.is_empty() {
        let (key, value, tail) = split_param(rest).ok_or(Malformed)?;
        rest = tail;
        if key == SvcParamKey::INVALID {
            return Err(SvcParamsError::ReservedKey(key));
        }
        match previous {
            Some(p) if p == key => return Err(Duplicate(key)),
            Some(p) if p > key => return Err(Malformed),
            _ => previous = Some(key),
        }
        let needs_elements = matches!(
            key,
            SvcParamKey::MANDATORY
                | SvcParamKey::ALPN
                | SvcParamKey::IPV4HINT
                | SvcParamKey::ECH
                | SvcParamKey::IPV6HINT
        );
        if needs_elements && value.is_empty() {
            return Err(Empty(key));
        }
        let valid = match key {
            SvcParamKey::MANDATORY => {
                let (keys, odd) = value.as_chunks::<2>();
                if let Some(pair) = keys.windows(2).find(|p| p[0] >= p[1]) {
                    let error = if pair[0] == pair[1] {
                        MandatoryTwice(SvcParamKey(u16::from_be_bytes(pair[0])))
                    } else {
                        Malformed
                    };
                    return Err(error);
                }
                mandatory = keys;
                odd.is_empty()
            }
            SvcParamKey::ALPN => {
                alpn = true;
                let mut ids = value;
                while let Some((&len, tail)) = ids.split_first() {
                    if len == 0 {
                        return Err(Empty(key));
                    }
                    let (_, tail) = tail.split_at_checked(usize::from(len)).ok_or(Malformed)?;
                    ids = tail;
                }
                true
            }
            SvcParamKey::NO_DEFAULT_ALPN => {
                no_default_alpn = true;
                value.is_empty()
            }
            SvcParamKey::PORT => value.len() == 2,
            SvcParamKey::IPV4HINT => value.len() % 4 == 0,
            SvcParamKey::IPV6HINT => value.len() % 16 == 0,
            SvcParamKey::DOHPATH => str::from_utf8(value).is_ok(),
            SvcParamKey::DOCPATH => length_prefixed(value).is_some(),
            _ => true,
        };
        if !valid {
            return Err(Malformed);
        }
    }
    if no_default_alpn && !alpn {
        return Err(NoDefaultAlpnWithoutAlpn);
    }
    // Both lists are strictly increasing by now: one merge walk, linear in the RDATA.
    let mut keys = core::iter::from_fn({
        let mut rest = wire;
        move || {
            let (key, _, tail) = split_param(rest)?;
            rest = tail;
            Some(key)
        }
    });
    for &key in mandatory {
        let key = SvcParamKey(u16::from_be_bytes(key));
        let present = keys.by_ref().find(|&k| k >= key) == Some(key);
        if key == SvcParamKey::MANDATORY || !present {
            return Err(BadMandatory(key));
        }
    }
    Ok(())
}

/// A SVCB or HTTPS record: priority 0 is `AliasMode`, anything else `ServiceMode` (RFC 9460 §2.4).
///
/// Its wire form fits the 65535 bytes of an RDATA.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Svcb<'a> {
    priority: u16,
    target: Name<'a>,
    params: SvcParams<'a>,
}

impl<'a> Svcb<'a> {
    /// A record of `priority`, `target` and `params`.
    ///
    /// # Errors
    ///
    /// [`SvcParamsError::TooLong`] when the three take more than 65535 bytes.
    pub fn new(
        priority: u16,
        target: Name<'a>,
        params: SvcParams<'a>,
    ) -> Result<Self, SvcParamsError> {
        if PRIORITY_LEN + target.wire_len() + params.0.len() > MAX_RDATA_LEN {
            return Err(SvcParamsError::TooLong);
        }
        Ok(Self {
            priority,
            target,
            params,
        })
    }

    /// `SvcPriority`; 0 makes this an alias to the target.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// `TargetName`; the root means "the owner name itself" in `ServiceMode` and "no service" in `AliasMode`.
    #[must_use]
    pub const fn target(&self) -> &Name<'a> {
        &self.target
    }

    /// The service parameters.
    #[must_use]
    pub const fn params(&self) -> &SvcParams<'a> {
        &self.params
    }

    /// The same record data, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Svcb<'static> {
        Svcb {
            priority: self.priority,
            target: self.target.into_owned(),
            params: self.params.into_owned(),
        }
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let priority = r.u16()?;
        let target = Name::decode_uncompressed(r)?;
        let params = r.rest();
        check(params).map_err(|e| {
            r.error(DecodeErrorKind::Invalid(match e {
                SvcParamsError::Malformed => "malformed service parameters",
                _ => "inconsistent service parameters",
            }))
        })?;
        Ok(Self {
            priority,
            target,
            params: SvcParams(Cow::Borrowed(params)),
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.priority)?;
        self.target.encode(w)?;
        w.put_bytes(&self.params.0)
    }
}

impl Svcb<'static> {
    /// Reads `priority target key=value...`, parameters in any order (RFC 9460 §2.1).
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let priority = f.number("SVCB priority")?;
        let target = f.name("SVCB target")?;
        let mut params = Vec::new();
        let mut tokens = Vec::new();
        f.quoted_pairs();
        while let Some(token) = f.next_opt()? {
            params.push(SvcParam::from_text(token.raw).map_err(|kind| token.error(kind))?);
            tokens.push((token, params.last().map(SvcParam::key)));
        }
        // The error points at the parameter it names, else at the first one.
        let at = |e: SvcParamsError| {
            let named = match e {
                SvcParamsError::Duplicate(k)
                | SvcParamsError::Empty(k)
                | SvcParamsError::ReservedKey(k) => Some(k),
                SvcParamsError::BadMandatory(_) | SvcParamsError::MandatoryTwice(_) => {
                    Some(SvcParamKey::MANDATORY)
                }
                SvcParamsError::NoDefaultAlpnWithoutAlpn => Some(SvcParamKey::NO_DEFAULT_ALPN),
                _ => None,
            };
            let token = tokens
                .iter()
                .rev()
                .find(|(_, key)| named.is_some() && *key == named)
                .or(tokens.first())
                .map(|(t, _)| *t);
            let kind = TextErrorKind::SvcParams(e);
            token.map_or_else(|| f.end_error(kind), |t| t.error(kind))
        };
        let params = SvcParams::new(params).map_err(at)?;
        Self::new(priority, target, params).map_err(at)
    }
}

/// `priority target key=value...`, parameters in key order.
impl fmt::Display for Svcb<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.priority, self.target)?;
        for param in &self.params {
            write!(f, " {param}")?;
        }
        Ok(())
    }
}

impl SvcParam {
    /// Reads `key` or `key=value`, the value a character-string then, for lists, comma-separated items
    /// (RFC 9460 §2.1, appendix A). A missing value is empty. A key written `keyNNNNN` takes its value in wire
    /// form, whatever the key (RFC 9460 §2.1: `key1=\002h2` is `alpn=h2`).
    fn from_text(raw: &[u8]) -> Result<Self, TextErrorKind> {
        let (name, value) = match raw.iter().position(|&b| b == b'=') {
            Some(at) => (raw.get(..at), raw.get(at + 1..)),
            None => (Some(raw), None),
        };
        let name = name.unwrap_or_default();
        let key =
            SvcParamKey::from_text(name).ok_or(TextErrorKind::Invalid("SVCB parameter key"))?;
        let value = value.map(text::unescape).transpose()?.unwrap_or_default();
        if name.starts_with(b"key") {
            return Self::from_wire_value(key, &value);
        }
        Ok(match key {
            SvcParamKey::MANDATORY => {
                Self::Mandatory(items(&value, "mandatory key", SvcParamKey::from_text)?)
            }
            SvcParamKey::ALPN => Self::Alpn(escaped_items(&value, false)?),
            SvcParamKey::NO_DEFAULT_ALPN if value.is_empty() => Self::NoDefaultAlpn,
            SvcParamKey::NO_DEFAULT_ALPN => {
                return Err(TextErrorKind::Invalid(
                    "no-default-alpn, which takes no value",
                ));
            }
            SvcParamKey::PORT => {
                Self::Port(text::number(&value).ok_or(TextErrorKind::Invalid("port"))?)
            }
            SvcParamKey::IPV4HINT => Self::Ipv4Hint(items(&value, "ipv4hint address", address)?),
            SvcParamKey::ECH => Self::Ech(
                decode_base64(&value)
                    .ok_or(TextErrorKind::Invalid("ech, base64"))?
                    .into(),
            ),
            SvcParamKey::IPV6HINT => Self::Ipv6Hint(items(&value, "ipv6hint address", address)?),
            SvcParamKey::DOHPATH => Self::DohPath(
                String::from_utf8(value)
                    .map_err(|_| TextErrorKind::Invalid("dohpath, not UTF-8"))?,
            ),
            SvcParamKey::DOCPATH => Self::DocPath(escaped_items(&value, true)?),
            _ => Self::Unknown {
                key,
                value: value.into(),
            },
        })
    }
}

impl SvcParam {
    /// The parameter of `key` whose wire value is `value`, which must read back to the same bytes.
    fn from_wire_value(key: SvcParamKey, value: &[u8]) -> Result<Self, TextErrorKind> {
        let invalid = TextErrorKind::Invalid("SVCB parameter value in wire form");
        let param = Self::parse(key, value).ok_or(invalid)?;
        let mut wire = Vec::with_capacity(value.len());
        param.encode_value(&mut wire).map_err(|_| invalid)?;
        if wire != value {
            return Err(invalid);
        }
        Ok(param)
    }
}

/// Parses the comma-separated items of a value without escapes (RFC 9460 appendix A.1); an empty value is an
/// empty list, left for [`SvcParams::new`] to refuse.
fn items<T>(
    value: &[u8],
    what: &'static str,
    parse: impl Fn(&[u8]) -> Option<T>,
) -> Result<Vec<T>, TextErrorKind> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(|&b| b == b',')
        .map(|item| parse(item).ok_or(TextErrorKind::Invalid(what)))
        .collect()
}

fn address<T: core::str::FromStr>(text: &[u8]) -> Option<T> {
    str::from_utf8(text).ok()?.parse().ok()
}

/// Splits an `alpn` or `docpath` value on commas, `\,` and `\\` standing for a comma and a backslash in an item
/// (RFC 9460 appendix A.1). An empty value has no item; `docpath` allows empty ones (`empty_items`), as in `a,,b`.
fn escaped_items(value: &[u8], empty_items: bool) -> Result<Vec<Box<[u8]>>, TextErrorKind> {
    let invalid = TextErrorKind::Invalid("alpn identifier or docpath segment");
    let mut ids = Vec::new();
    if value.is_empty() {
        return Ok(ids);
    }
    let mut id = Vec::new();
    let mut bytes = value.iter();
    while let Some(&b) = bytes.next() {
        match b {
            b'\\' => match bytes.next() {
                Some(&escaped @ (b',' | b'\\')) => id.push(escaped),
                _ => return Err(invalid),
            },
            b',' if id.is_empty() && !empty_items => return Err(invalid),
            b',' => ids.push(core::mem::take(&mut id).into()),
            _ => id.push(b),
        }
    }
    if id.is_empty() && !empty_items {
        return Err(invalid);
    }
    ids.push(id.into());
    Ok(ids)
}

/// `key=value`, or `key` alone for `no-default-alpn`; lists comma-separated, free-form values quoted.
impl fmt::Display for SvcParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // One empty segment reads as no segment in a list, so it goes in wire form (RFC 9460 §2.1).
        if let Self::DocPath(segments) = self
            && let [segment] = segments.as_slice()
            && segment.is_empty()
        {
            return write!(f, "key{}={}", SvcParamKey::DOCPATH.0, Quoted(&[0]));
        }
        write!(f, "{}", self.key())?;
        match self {
            Self::Mandatory(keys) => list(f, keys),
            Self::DocPath(items) if items.is_empty() => Ok(()),
            Self::Alpn(items) | Self::DocPath(items) => {
                write!(f, "={}", Quoted(&escape_items(items)))
            }
            Self::NoDefaultAlpn => Ok(()),
            Self::Port(port) => write!(f, "={port}"),
            Self::Ipv4Hint(hints) => list(f, hints),
            Self::Ech(config) => write!(f, "={}", Base64(config)),
            Self::Ipv6Hint(hints) => list(f, hints),
            Self::DohPath(path) => write!(f, "={}", Quoted(path.as_bytes())),
            Self::Unknown { value, .. } => write!(f, "={}", Quoted(value)),
        }
    }
}

/// The items of `alpn` or `docpath` as a comma-separated list, `,` and `\` in an item escaped by a `\`.
fn escape_items(items: &[Box<[u8]>]) -> Vec<u8> {
    let mut value = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            value.push(b',');
        }
        for &b in &**item {
            if matches!(b, b',' | b'\\') {
                value.push(b'\\');
            }
            value.push(b);
        }
    }
    value
}

/// Writes `=` and the items separated by commas.
fn list<T: fmt::Display>(f: &mut fmt::Formatter<'_>, items: &[T]) -> fmt::Result {
    for (i, item) in items.iter().enumerate() {
        f.write_str(if i == 0 { "=" } else { "," })?;
        write!(f, "{item}")?;
    }
    Ok(())
}
