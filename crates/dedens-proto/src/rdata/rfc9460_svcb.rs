//! SVCB and HTTPS: service binding (RFC 9460), with the `dohpath` key of RFC 9461.
//!
//! The wire form is `priority, target (never compressed), (key, length, value)*` with keys strictly increasing
//! (RFC 9460 §2.2). [`SvcParams`] only holds a list that is valid and consistent (RFC 9460 §2.4), so a decoded
//! record can be encoded again and a built one is never rejected by a peer for its parameters.

use core::net::{Ipv4Addr, Ipv6Addr};

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

    fn decode(key: SvcParamKey, r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let param = match key {
            SvcParamKey::MANDATORY => {
                let mut keys = Vec::with_capacity(r.remaining() / 2);
                while !r.is_empty() {
                    keys.push(SvcParamKey(r.u16()?));
                }
                if keys.windows(2).any(|p| p[0] >= p[1]) {
                    return Err(r.error(DecodeErrorKind::Invalid(
                        "mandatory keys not strictly increasing",
                    )));
                }
                Self::Mandatory(keys)
            }
            SvcParamKey::ALPN => {
                let mut ids = Vec::new();
                while !r.is_empty() {
                    let len = usize::from(r.u8()?);
                    ids.push(r.bytes(len)?.into());
                }
                Self::Alpn(ids)
            }
            SvcParamKey::NO_DEFAULT_ALPN => Self::NoDefaultAlpn,
            SvcParamKey::PORT => Self::Port(r.u16()?),
            SvcParamKey::IPV4HINT => {
                let mut hints = Vec::with_capacity(r.remaining() / 4);
                while !r.is_empty() {
                    hints.push(Ipv4Addr::from(r.array::<4>()?));
                }
                Self::Ipv4Hint(hints)
            }
            SvcParamKey::ECH => Self::Ech(r.rest().into()),
            SvcParamKey::IPV6HINT => {
                let mut hints = Vec::with_capacity(r.remaining() / 16);
                while !r.is_empty() {
                    hints.push(Ipv6Addr::from(r.array::<16>()?));
                }
                Self::Ipv6Hint(hints)
            }
            SvcParamKey::DOHPATH => {
                let bytes = r.rest();
                let path = str::from_utf8(bytes)
                    .map_err(|_| r.error(DecodeErrorKind::Invalid("dohpath is not UTF-8")))?;
                Self::DohPath(path.into())
            }
            _ => Self::Unknown {
                key,
                value: r.rest().into(),
            },
        };
        if r.is_empty() {
            Ok(param)
        } else {
            Err(r.error(DecodeErrorKind::Invalid(
                "trailing bytes in a service parameter",
            )))
        }
    }

    fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::Mandatory(keys) => keys.iter().try_for_each(|k| w.put_u16(k.0)),
            Self::Alpn(ids) => ids.iter().try_for_each(|id| {
                let len = u8::try_from(id.len()).map_err(|_| EncodeError::BufferFull)?;
                w.put_u8(len)?;
                w.put_bytes(id)
            }),
            Self::NoDefaultAlpn => Ok(()),
            Self::Port(port) => w.put_u16(*port),
            Self::Ipv4Hint(hints) => hints.iter().try_for_each(|a| w.put_bytes(&a.octets())),
            Self::Ech(config) => w.put_bytes(config),
            Self::Ipv6Hint(hints) => hints.iter().try_for_each(|a| w.put_bytes(&a.octets())),
            Self::DohPath(path) => w.put_bytes(path.as_bytes()),
            Self::Unknown { value, .. } => w.put_bytes(value),
        }
    }
}

/// A parameter list that breaks RFC 9460 (§2.2, §2.4.3, §7, §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
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
}

/// The parameters of a SVCB or HTTPS record: sorted by key, each key once, internally consistent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SvcParams(Vec<SvcParam>);

impl SvcParams {
    /// Parameters from `params` in any order; sorts them by key.
    ///
    /// # Errors
    ///
    /// [`SvcParamsError`] when a key repeats, a value that needs elements has none, `mandatory` lists itself or a
    /// missing key, or an unknown parameter uses key 0 to 7 or 65535.
    pub fn new(mut params: Vec<SvcParam>) -> Result<Self, SvcParamsError> {
        params.sort_by_key(SvcParam::key);
        if let Some(pair) = params.windows(2).find(|p| p[0].key() == p[1].key()) {
            return Err(SvcParamsError::Duplicate(pair[0].key()));
        }
        for param in &mut params {
            let key = param.key();
            let empty = match param {
                SvcParam::Mandatory(keys) => {
                    keys.sort_unstable();
                    if let Some(pair) = keys.windows(2).find(|p| p[0] == p[1]) {
                        return Err(SvcParamsError::Duplicate(pair[0]));
                    }
                    keys.is_empty()
                }
                SvcParam::Alpn(ids) => {
                    ids.is_empty() || ids.iter().any(|id| id.is_empty() || id.len() > 255)
                }
                SvcParam::Ipv4Hint(hints) => hints.is_empty(),
                SvcParam::Ipv6Hint(hints) => hints.is_empty(),
                SvcParam::Unknown { key, .. } if key.is_known() || *key == SvcParamKey::INVALID => {
                    return Err(SvcParamsError::ReservedKey(*key));
                }
                SvcParam::NoDefaultAlpn
                | SvcParam::Port(_)
                | SvcParam::Ech(_)
                | SvcParam::DohPath(_)
                | SvcParam::Unknown { .. } => false,
            };
            if empty {
                return Err(SvcParamsError::Empty(key));
            }
        }
        let list = Self(params);
        if let Some(SvcParam::Mandatory(keys)) = list.get(SvcParamKey::MANDATORY)
            && let Some(bad) = keys
                .iter()
                .find(|k| **k == SvcParamKey::MANDATORY || list.get(**k).is_none())
        {
            return Err(SvcParamsError::BadMandatory(*bad));
        }
        Ok(list)
    }

    /// The parameters, by increasing key.
    #[must_use]
    pub fn as_slice(&self) -> &[SvcParam] {
        &self.0
    }

    /// The parameter with `key`, if present.
    #[must_use]
    pub fn get(&self, key: SvcParamKey) -> Option<&SvcParam> {
        self.0
            .binary_search_by_key(&key, SvcParam::key)
            .ok()
            .and_then(|i| self.0.get(i))
    }
}

/// A SVCB or HTTPS record: priority 0 is `AliasMode`, anything else `ServiceMode` (RFC 9460 §2.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Svcb {
    /// `SvcPriority`; 0 makes this an alias to `target`.
    pub priority: u16,
    /// `TargetName`; the root means "the owner name itself" in `ServiceMode` and "no service" in `AliasMode`.
    pub target: Name,
    /// The service parameters.
    pub params: SvcParams,
}

impl Svcb {
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let priority = r.u16()?;
        let target = Name::decode_uncompressed(r)?;
        let mut params = Vec::new();
        let mut previous: Option<SvcParamKey> = None;
        while !r.is_empty() {
            let key = SvcParamKey(r.u16()?);
            if key == SvcParamKey::INVALID || previous.is_some_and(|p| p >= key) {
                return Err(r.error(DecodeErrorKind::Invalid(
                    "service parameter keys not strictly increasing",
                )));
            }
            previous = Some(key);
            let len = usize::from(r.u16()?);
            let mut value = r.sub(len)?;
            params.push(SvcParam::decode(key, &mut value)?);
        }
        let params = SvcParams::new(params)
            .map_err(|_| r.error(DecodeErrorKind::Invalid("inconsistent service parameters")))?;
        Ok(Self {
            priority,
            target,
            params,
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.priority)?;
        self.target.encode(w)?;
        for param in self.params.as_slice() {
            w.put_u16(param.key().0)?;
            let at = w.reserve_u16()?;
            param.encode_value(w)?;
            let len = u16::try_from(w.len() - at - 2).map_err(|_| EncodeError::BufferFull)?;
            w.patch_u16(at, len);
        }
        Ok(())
    }
}
