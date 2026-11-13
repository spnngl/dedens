//! DNS stamps, the `sdns://` strings that name a `DNSCrypt` resolver or an Anonymized `DNSCrypt` relay
//! (draft-denis-dns-stamps-02, sections "DNS Stamps Format Overview", "`DNSCrypt` Stamps" and "Anonymized `DNSCrypt` Relay
//! Stamps"; D102): sans-IO, parsed into [`Stamp`] and written back as they were read.
//!
//! The other kinds the draft defines (plain DNS, `DoH`, `DoT`, `DoQ`, Oblivious `DoH`) are refused, the error naming the
//! kind. Read as the draft says, the properties' reserved bits ignored, but for one thing: a port left out of a
//! relay's address is [`DEFAULT_PORT`] (the draft makes it mandatory there; 237 of the 315 published relay stamps leave
//! it out, and `dnscrypt-proxy` reads them). Not checked: that the provider key is a point of the curve, which is the
//! `DNSCrypt` core's.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::str::FromStr;

use dedens_proto::{Name, decode_base64url, encode_base64url};

/// The port of a stamp's address that names none (draft, "`DNSCrypt` Stamps").
pub const DEFAULT_PORT: u16 = 443;

/// How a stamp starts.
const SCHEME: &str = "sdns://";
/// The protocol identifier of a `DNSCrypt` stamp.
const KIND_DNSCRYPT: u8 = 0x01;
/// The protocol identifier of an Anonymized `DNSCrypt` relay stamp.
const KIND_RELAY: u8 = 0x81;
/// The length of a provider public key, an `Ed25519` one.
const KEY_LEN: usize = 32;

/// A DNS stamp that names a `DNSCrypt` resolver or a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stamp {
    /// A `DNSCrypt` resolver (identifier `0x01`).
    DnsCrypt(DnsCrypt),
    /// An Anonymized `DNSCrypt` relay (identifier `0x81`).
    Relay(Relay),
}

/// A `DNSCrypt` resolver: where it is, and whose certificates to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCrypt {
    /// What the operator says of the resolver.
    pub properties: Properties,
    /// Where the resolver listens.
    pub address: Endpoint,
    /// The `Ed25519` key the resolver's certificates are signed with.
    pub public_key: [u8; KEY_LEN],
    /// The name the certificates are asked under, as a TXT question (`2.dnscrypt-cert.example.com`).
    pub provider_name: ProviderName,
}

/// The provider name of a resolver: a DNS name, in a stamp as its presentation form without the final dot (draft,
/// "`DNSCrypt` Stamps"), so only a name whose text is that, and fits the one-byte length of a field, is one: never the
/// root, and never a name of bytes that need escapes to the point of 256 characters. The text a name is read from
/// is the text it is written as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderName(Name<'static>);

impl ProviderName {
    /// The name, for the TXT question the certificates are asked under.
    #[must_use]
    pub fn name(&self) -> &Name<'static> {
        &self.0
    }

    /// The text of the name: its presentation form without the final dot.
    fn text(&self) -> String {
        let mut text = self.0.to_string();
        text.pop();
        text
    }
}

impl FromStr for ProviderName {
    type Err = StampError;

    fn from_str(text: &str) -> Result<Self, StampError> {
        let bad = || StampError::ProviderName(text.to_owned());
        let name: Name<'static> = text.parse().map_err(|_| bad())?;
        let own = Self(name);
        if own.0.is_root() || own.text() != text || text.len() > usize::from(u8::MAX) {
            return Err(bad());
        }
        Ok(own)
    }
}

impl fmt::Display for ProviderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

/// An Anonymized `DNSCrypt` relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relay {
    /// Where the relay listens.
    pub address: Endpoint,
}

impl FromStr for Relay {
    type Err = StampError;

    /// Reads a relay as a client is told of one: a relay stamp (`sdns://gQ...`) or the address alone, `192.0.2.1` or
    /// `[2001:db8::1]:8443`, its port [`DEFAULT_PORT`] when left out (D100).
    fn from_str(text: &str) -> Result<Self, StampError> {
        if !text.starts_with(SCHEME) {
            return Ok(Self {
                address: Endpoint::parse(text)?,
            });
        }
        match text.parse()? {
            Stamp::Relay(relay) => Ok(relay),
            Stamp::DnsCrypt(_) => Err(StampError::NotRelay),
        }
    }
}

/// What a resolver's operator says of it: bits 0 to 2 of the stamp's properties (draft, "Properties Field"), the
/// reserved ones ignored when read and zero when written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Properties {
    /// The resolver validates DNSSEC signatures.
    pub dnssec: bool,
    /// The resolver keeps no query logs.
    pub no_logs: bool,
    /// The resolver does not filter or block names.
    pub no_filter: bool,
}

impl Properties {
    fn from_bits(bits: u64) -> Self {
        Self {
            dnssec: bits & 1 != 0,
            no_logs: bits & 2 != 0,
            no_filter: bits & 4 != 0,
        }
    }

    fn bits(self) -> u64 {
        u64::from(self.dnssec) | u64::from(self.no_logs) << 1 | u64::from(self.no_filter) << 2
    }
}

/// An IP address and the port the stamp gives with it, if any: `192.0.2.1`, `192.0.2.1:5353`, `[2001:db8::1]`,
/// `[2001:db8::1]:5353`. The port is kept as read, so that a stamp is written as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    /// The address.
    pub ip: IpAddr,
    /// The port, from 1 to 65535; `None` for [`DEFAULT_PORT`].
    pub port: Option<NonZeroU16>,
}

impl Endpoint {
    /// The address to connect to: the port the stamp gives, else [`DEFAULT_PORT`].
    #[must_use]
    pub fn socket_addr(self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port.map_or(DEFAULT_PORT, NonZeroU16::get))
    }

    /// Reads the text of a stamp's address: an `IPv6` address is in brackets, an `IPv4` one is not.
    fn parse(text: &str) -> Result<Self, StampError> {
        let bad = || StampError::Address(text.to_owned());
        let (ip, port) = if let Some(rest) = text.strip_prefix('[') {
            let (ip, after) = rest.split_once(']').ok_or_else(bad)?;
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':').ok_or_else(bad)?),
            };
            (IpAddr::V6(ip.parse::<Ipv6Addr>().map_err(|_| bad())?), port)
        } else {
            let (ip, port) = match text.split_once(':') {
                Some((ip, port)) => (ip, Some(port)),
                None => (text, None),
            };
            (IpAddr::V4(ip.parse::<Ipv4Addr>().map_err(|_| bad())?), port)
        };
        // Digits alone: `u16`'s own reading takes a leading `+`.
        let port = port
            .map(|digits| {
                digits
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| digits.parse::<NonZeroU16>().ok())
                    .flatten()
                    .ok_or_else(bad)
            })
            .transpose()?;
        let endpoint = Self { ip, port };
        // One text for an address: `[2001:0DB8::1]` and `192.0.2.1:080` would be written as other text.
        (endpoint.to_string() == text)
            .then_some(endpoint)
            .ok_or_else(bad)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}")?,
            IpAddr::V6(ip) => write!(f, "[{ip}]")?,
        }
        match self.port {
            Some(port) => write!(f, ":{port}"),
            None => Ok(()),
        }
    }
}

/// Why a stamp was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StampError {
    /// The text does not start with `sdns://`.
    #[error("a stamp starts with `sdns://`")]
    Scheme,
    /// The text after the scheme is not base64url without padding, in its one canonical form.
    #[error("the payload is not base64url without padding")]
    Base64,
    /// The payload has no protocol identifier.
    #[error("the payload is empty")]
    Empty,
    /// A kind the draft defines and this module does not read.
    #[error("{name} stamps (kind 0x{kind:02x}) are not supported")]
    Unsupported {
        /// The protocol identifier.
        kind: u8,
        /// The kind's name.
        name: &'static str,
    },
    /// A protocol identifier the draft does not define.
    #[error("unknown stamp kind 0x{0:02x}")]
    UnknownKind(u8),
    /// The payload ends inside a field, or a length goes past its end.
    #[error("the {0} is cut short")]
    Truncated(&'static str),
    /// The payload goes on after its last field.
    #[error("{0} bytes after the last field")]
    Trailing(usize),
    /// The address is not an IP address with an optional port from 1 to 65535, in the one text it is written as.
    #[error("the address {0:?} is not an IP address in its canonical text, with a port or not")]
    Address(String),
    /// A stamp that names a relay is one of a `DNSCrypt` resolver.
    #[error("a relay is a relay stamp (0x81) or an address, not a DNSCrypt resolver's stamp")]
    NotRelay,
    /// The provider public key is not 32 bytes.
    #[error("the provider public key is {0} bytes, not 32")]
    KeyLength(usize),
    /// The provider name is not a DNS name written without its final dot.
    #[error("the provider name {0:?} is not a DNS name without a final dot")]
    ProviderName(String),
}

impl FromStr for Stamp {
    type Err = StampError;

    fn from_str(text: &str) -> Result<Self, StampError> {
        let payload = text.strip_prefix(SCHEME).ok_or(StampError::Scheme)?;
        let payload = decode_base64url(payload.as_bytes()).ok_or(StampError::Base64)?;
        Self::decode(&payload)
    }
}

impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}", encode_base64url(&self.encode()))
    }
}

impl Stamp {
    fn decode(payload: &[u8]) -> Result<Self, StampError> {
        let (&kind, rest) = payload.split_first().ok_or(StampError::Empty)?;
        let mut fields = Fields(rest);
        let stamp = match kind {
            KIND_DNSCRYPT => {
                let properties = Properties::from_bits(fields.properties()?);
                let address = Endpoint::parse(&fields.text("address")?)?;
                let key = fields.length_prefixed("provider public key")?;
                let public_key = key
                    .try_into()
                    .map_err(|_| StampError::KeyLength(key.len()))?;
                let provider_name =
                    String::from_utf8_lossy(fields.length_prefixed("provider name")?).parse()?;
                Self::DnsCrypt(DnsCrypt {
                    properties,
                    address,
                    public_key,
                    provider_name,
                })
            }
            KIND_RELAY => Self::Relay(Relay {
                address: Endpoint::parse(&fields.text("address")?)?,
            }),
            _ => {
                return Err(match kind_name(kind) {
                    Some(name) => StampError::Unsupported { kind, name },
                    None => StampError::UnknownKind(kind),
                });
            }
        };
        match fields.0.len() {
            0 => Ok(stamp),
            left => Err(StampError::Trailing(left)),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::DnsCrypt(resolver) => {
                out.push(KIND_DNSCRYPT);
                out.extend_from_slice(&resolver.properties.bits().to_le_bytes());
                push_length_prefixed(&mut out, resolver.address.to_string().as_bytes());
                push_length_prefixed(&mut out, &resolver.public_key);
                push_length_prefixed(&mut out, resolver.provider_name.text().as_bytes());
            }
            Self::Relay(relay) => {
                out.push(KIND_RELAY);
                push_length_prefixed(&mut out, relay.address.to_string().as_bytes());
            }
        }
        out
    }
}

/// The name of a protocol identifier the draft defines and this module refuses.
fn kind_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0x00 => "plain DNS",
        0x02 => "DNS-over-HTTPS",
        0x03 => "DNS-over-TLS",
        0x04 => "DNS-over-QUIC",
        0x05 => "Oblivious DoH target",
        0x85 => "Oblivious DoH relay",
        _ => return None,
    })
}

/// Appends a field behind its length, one byte (draft, `LP(x)`).
fn push_length_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    // The longest field is a provider name, which `ProviderName` keeps to 255 bytes.
    out.push(u8::try_from(field.len()).expect("a field of at most 255 bytes"));
    out.extend_from_slice(field);
}

/// The fields of a payload not read yet.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn properties(&mut self) -> Result<u64, StampError> {
        let (bits, rest) = self
            .0
            .split_first_chunk()
            .ok_or(StampError::Truncated("properties"))?;
        self.0 = rest;
        Ok(u64::from_le_bytes(*bits))
    }

    /// A field behind its one-byte length.
    fn length_prefixed(&mut self, field: &'static str) -> Result<&'a [u8], StampError> {
        let (&len, rest) = self.0.split_first().ok_or(StampError::Truncated(field))?;
        let (value, rest) = rest
            .split_at_checked(usize::from(len))
            .ok_or(StampError::Truncated(field))?;
        self.0 = rest;
        Ok(value)
    }

    /// A field behind its length, as text: bytes that are not UTF-8 are no address.
    fn text(&mut self, field: &'static str) -> Result<String, StampError> {
        let bytes = self.length_prefixed(field)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}
