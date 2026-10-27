//! Protocol codes (D19): newtypes over the wire integer with named constants.
//!
//! Every wire value is representable and has one form; an unassigned or unsupported value is just another
//! number, written `TYPE65280`-style (RFC 3597 §5).

/// Defines a code newtype: the constants, `mnemonic()`, `Display`/`Debug` and the integer conversions.
macro_rules! code_type {
    (
        $(#[$meta:meta])*
        $name:ident($int:ty), $fallback:literal;
        $( $(#[$cmeta:meta])* $konst:ident = $value:literal, $text:literal; )*
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub $int);

        impl $name {
            $( $(#[$cmeta])* pub const $konst: Self = Self($value); )*

            /// The registered mnemonic, when the value has one.
            #[must_use]
            pub const fn mnemonic(self) -> Option<&'static str> {
                match self.0 {
                    $( $value => Some($text), )*
                    _ => None,
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self.mnemonic() {
                    Some(text) => f.write_str(text),
                    None => write!(f, concat!($fallback, "{}"), self.0),
                }
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(self, f)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::codes::UnknownCode;

            /// Reads a mnemonic, any case, or the generic form: the fallback prefix and the decimal value.
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $( if s.eq_ignore_ascii_case($text) { return Ok(Self::$konst); } )*
                let unknown = $crate::codes::UnknownCode { prefix: $fallback };
                let value = s
                    .get(..$fallback.len())
                    .filter(|prefix| prefix.eq_ignore_ascii_case($fallback))
                    .and_then(|_| s.get($fallback.len()..))
                    .ok_or(unknown)?;
                $crate::text::number(value.as_bytes()).map(Self).ok_or(unknown)
            }
        }

        impl From<$int> for $name {
            fn from(value: $int) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $int {
            fn from(code: $name) -> Self {
                code.0
            }
        }
    };
}

pub(crate) use code_type;

/// Text that is neither a mnemonic nor the generic form of a code (`TYPE65280`, RFC 3597 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("neither a mnemonic nor {prefix} followed by a number")]
pub struct UnknownCode {
    /// The prefix of the generic form, such as `TYPE`.
    pub prefix: &'static str,
}

code_type! {
    /// Resource record TYPE or QTYPE (RFC 1035 §3.2.2, §3.2.3).
    RecordType(u16), "TYPE";
    /// Host address (RFC 1035 §3.4.1).
    A = 1, "A";
    /// Authoritative name server (RFC 1035 §3.3.11).
    NS = 2, "NS";
    /// Mail destination, obsolete (RFC 1035 §3.3.4).
    MD = 3, "MD";
    /// Mail forwarder, obsolete (RFC 1035 §3.3.5).
    MF = 4, "MF";
    /// Canonical name (RFC 1035 §3.3.1).
    CNAME = 5, "CNAME";
    /// Start of authority (RFC 1035 §3.3.13).
    SOA = 6, "SOA";
    /// Mailbox domain name, experimental (RFC 1035 §3.3.3).
    MB = 7, "MB";
    /// Mail group member, experimental (RFC 1035 §3.3.6).
    MG = 8, "MG";
    /// Mail rename domain name, experimental (RFC 1035 §3.3.8).
    MR = 9, "MR";
    /// Domain name pointer (RFC 1035 §3.3.12).
    PTR = 12, "PTR";
    /// Host information (RFC 1035 §3.3.2).
    HINFO = 13, "HINFO";
    /// Mailbox or mail list information, experimental (RFC 1035 §3.3.7).
    MINFO = 14, "MINFO";
    /// Mail exchange (RFC 1035 §3.3.9).
    MX = 15, "MX";
    /// Text strings (RFC 1035 §3.3.14).
    TXT = 16, "TXT";
    /// Responsible person (RFC 1183 §2.2).
    RP = 17, "RP";
    /// AFS database location (RFC 1183 §1).
    AFSDB = 18, "AFSDB";
    /// Route through (RFC 1183 §3.3).
    RT = 21, "RT";
    /// Signature, obsolete (RFC 2535 §4).
    SIG = 24, "SIG";
    /// X.400 mail mapping (RFC 2163 §4).
    PX = 26, "PX";
    /// IPv6 address (RFC 3596 §2.1).
    AAAA = 28, "AAAA";
    /// Next domain, obsolete (RFC 2535 §5).
    NXT = 30, "NXT";
    /// Service locator (RFC 2782).
    SRV = 33, "SRV";
    /// Naming authority pointer (RFC 3403 §4).
    NAPTR = 35, "NAPTR";
    /// EDNS pseudo-record (RFC 6891).
    OPT = 41, "OPT";
    /// Service binding (RFC 9460 §2).
    SVCB = 64, "SVCB";
    /// Service binding for HTTPS (RFC 9460 §9).
    HTTPS = 65, "HTTPS";
    /// Incremental zone transfer, QTYPE only (RFC 1995).
    IXFR = 251, "IXFR";
    /// Zone transfer, QTYPE only (RFC 1035 §3.2.3).
    AXFR = 252, "AXFR";
    /// All records, QTYPE only (RFC 1035 §3.2.3, RFC 8482).
    ANY = 255, "ANY";
    /// Certification authority authorization (RFC 8659).
    CAA = 257, "CAA";
}

code_type! {
    /// Resource record CLASS or QCLASS (RFC 1035 §3.2.4, §3.2.5).
    Class(u16), "CLASS";
    /// The Internet.
    IN = 1, "IN";
    /// Chaos.
    CH = 3, "CH";
    /// Hesiod.
    HS = 4, "HS";
    /// No class, in UPDATE (RFC 2136 §2.4).
    NONE = 254, "NONE";
    /// Any class, QCLASS only.
    ANY = 255, "ANY";
}

code_type! {
    /// Header OPCODE, 4 bits (RFC 1035 §4.1.1).
    Opcode(u8), "OPCODE";
    /// Standard query.
    QUERY = 0, "QUERY";
    /// Inverse query, obsolete (RFC 3425).
    IQUERY = 1, "IQUERY";
    /// Server status request.
    STATUS = 2, "STATUS";
    /// Zone change notification (RFC 1996).
    NOTIFY = 4, "NOTIFY";
    /// Dynamic update (RFC 2136).
    UPDATE = 5, "UPDATE";
    /// DNS Stateful Operations (RFC 8490).
    DSO = 6, "DSO";
}

code_type! {
    /// Response code, 12 bits: 4 in the header, the upper 8 in the OPT record (RFC 6891 §6.1.3).
    Rcode(u16), "RCODE";
    /// No error (RFC 1035 §4.1.1).
    NOERROR = 0, "NOERROR";
    /// Format error.
    FORMERR = 1, "FORMERR";
    /// Server failure.
    SERVFAIL = 2, "SERVFAIL";
    /// Non-existent domain.
    NXDOMAIN = 3, "NXDOMAIN";
    /// Not implemented.
    NOTIMP = 4, "NOTIMP";
    /// Query refused.
    REFUSED = 5, "REFUSED";
    /// Name exists when it should not (RFC 2136).
    YXDOMAIN = 6, "YXDOMAIN";
    /// `RRset` exists when it should not (RFC 2136).
    YXRRSET = 7, "YXRRSET";
    /// `RRset` that should exist does not (RFC 2136).
    NXRRSET = 8, "NXRRSET";
    /// Server not authoritative for the zone (RFC 2136).
    NOTAUTH = 9, "NOTAUTH";
    /// Name not in the zone (RFC 2136).
    NOTZONE = 10, "NOTZONE";
    /// DSO-TYPE not implemented (RFC 8490).
    DSOTYPENI = 11, "DSOTYPENI";
    /// Bad OPT version (RFC 6891 §6.1.3).
    BADVERS = 16, "BADVERS";
    /// Bad or missing server cookie (RFC 7873 §5.2.3).
    BADCOOKIE = 23, "BADCOOKIE";
}

impl Default for Opcode {
    fn default() -> Self {
        Self::QUERY
    }
}

impl Default for Rcode {
    fn default() -> Self {
        Self::NOERROR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_codes_print_as_rfc3597() {
        assert_eq!(RecordType(65280).to_string(), "TYPE65280");
        assert_eq!(Class(7).to_string(), "CLASS7");
    }

    #[test]
    fn known_codes_print_their_mnemonic() {
        assert_eq!(RecordType::AAAA.to_string(), "AAAA");
        assert_eq!(Rcode::NXDOMAIN.to_string(), "NXDOMAIN");
        assert_eq!(u16::from(RecordType::HTTPS), 65);
    }
}
