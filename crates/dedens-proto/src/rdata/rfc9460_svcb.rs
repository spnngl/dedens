//! SVCB and HTTPS: service binding (RFC 9460), with the `dohpath` key of RFC 9461.
//!
//! The wire form is `priority, target (never compressed), (key, length, value)*` with keys strictly increasing
//! (RFC 9460 §2.2). [`SvcParams`] only holds a list that is valid and consistent (RFC 9460 §2.4), so a decoded
//! record can be encoded again and a built one is never rejected by a peer for its parameters.

use core::net::{Ipv4Addr, Ipv6Addr};
use std::borrow::Cow;

use crate::codes::code_type;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::Name;
use crate::wire::{Reader, Writer};

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
}

impl SvcParamKey {
    /// Reserved, never valid on the wire (RFC 9460 §14.3.2).
    const INVALID: Self = Self(65535);

    /// Keys 0 to 7 have a typed [`SvcParam`] variant; they cannot be carried as [`SvcParam::Unknown`].
    const fn is_known(self) -> bool {
        self.0 <= Self::DOHPATH.0
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
    /// A key without a typed variant; its key is above 7 (RFC 9460 §2.2).
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
            SvcParamKey::ALPN => {
                let mut ids = Vec::new();
                let mut rest = value;
                while let Some((&len, tail)) = rest.split_first() {
                    let (id, tail) = tail.split_at_checked(usize::from(len))?;
                    ids.push(id.into());
                    rest = tail;
                }
                Self::Alpn(ids)
            }
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
            Self::Alpn(ids) => {
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

/// A parameter list that breaks RFC 9460 (§2.2, §2.4.3, §7, §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SvcParamsError {
    /// A key appears twice, as a parameter or in the `mandatory` list.
    #[error("service parameter {0} appears more than once")]
    Duplicate(SvcParamKey),
    /// A list-valued parameter has no element, or an ALPN identifier is empty.
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
    /// missing key, `no-default-alpn` comes without `alpn`, an unknown parameter uses key 0 to 7 or 65535, or a
    /// value is too long for the wire.
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
    use SvcParamsError::{BadMandatory, Duplicate, Empty, Malformed, NoDefaultAlpnWithoutAlpn};
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
                        Duplicate(SvcParamKey(u16::from_be_bytes(pair[0])))
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
            _ => true,
        };
        if !valid {
            return Err(Malformed);
        }
    }
    if no_default_alpn && !alpn {
        return Err(NoDefaultAlpnWithoutAlpn);
    }
    for &key in mandatory {
        let key = SvcParamKey(u16::from_be_bytes(key));
        let present = || Params(wire).any(|p| p.key() == key);
        if key == SvcParamKey::MANDATORY || !present() {
            return Err(BadMandatory(key));
        }
    }
    Ok(())
}

/// A SVCB or HTTPS record: priority 0 is `AliasMode`, anything else `ServiceMode` (RFC 9460 §2.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Svcb<'a> {
    /// `SvcPriority`; 0 makes this an alias to `target`.
    pub priority: u16,
    /// `TargetName`; the root means "the owner name itself" in `ServiceMode` and "no service" in `AliasMode`.
    pub target: Name<'a>,
    /// The service parameters.
    pub params: SvcParams<'a>,
}

impl<'a> Svcb<'a> {
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
