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

            /// [`FromStr`](::core::str::FromStr) on bytes, as zone files are read.
            pub(crate) fn from_bytes(s: &[u8]) -> Result<Self, $crate::codes::UnknownCode> {
                $( if s.eq_ignore_ascii_case($text.as_bytes()) { return Ok(Self::$konst); } )*
                let unknown = $crate::codes::UnknownCode { prefix: $fallback };
                s.split_at_checked($fallback.len())
                    .filter(|(prefix, _)| prefix.eq_ignore_ascii_case($fallback.as_bytes()))
                    .and_then(|(_, value)| $crate::text::number(value))
                    .map(Self)
                    .ok_or(unknown)
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
                Self::from_bytes(s.as_bytes())
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownCode {
    /// The prefix of the generic form, such as `TYPE`; empty when the generic form is the bare number.
    pub prefix: &'static str,
}

impl core::fmt::Display for UnknownCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.prefix.is_empty() {
            f.write_str("neither a mnemonic nor a number")
        } else {
            write!(
                f,
                "neither a mnemonic nor {} followed by a number",
                self.prefix
            )
        }
    }
}

impl core::error::Error for UnknownCode {}

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
    /// Key exchanger (RFC 2230 §3).
    KX = 36, "KX";
    /// Delegation name (RFC 6672 §2).
    DNAME = 39, "DNAME";
    /// EDNS pseudo-record (RFC 6891).
    OPT = 41, "OPT";
    /// Delegation signer (RFC 4034 §5).
    DS = 43, "DS";
    /// Signature over an `RRset` (RFC 4034 §3).
    RRSIG = 46, "RRSIG";
    /// Next secure record: the authenticated denial of existence (RFC 4034 §4).
    NSEC = 47, "NSEC";
    /// Zone public key (RFC 4034 §2).
    DNSKEY = 48, "DNSKEY";
    /// Hashed next secure record (RFC 5155 §3).
    NSEC3 = 50, "NSEC3";
    /// Parameters of the NSEC3 records of a zone (RFC 5155 §4).
    NSEC3PARAM = 51, "NSEC3PARAM";
    /// Delegation signer the child asks the parent to publish (RFC 7344 §3.1).
    CDS = 59, "CDS";
    /// DNSKEY the child asks the parent to publish as a DS (RFC 7344 §3.2).
    CDNSKEY = 60, "CDNSKEY";
    /// Service binding (RFC 9460 §2).
    SVCB = 64, "SVCB";
    /// Service binding for HTTPS (RFC 9460 §9).
    HTTPS = 65, "HTTPS";
    /// Non-existent name signalled by a compact denial of existence: a meta-TYPE that only appears in an NSEC
    /// type bitmap (RFC 9824 §2).
    NXNAME = 128, "NXNAME";
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
    /// DNSSEC algorithm number of DNSKEY, DS and RRSIG records (RFC 4034 appendix A.1, IANA "DNS Security
    /// Algorithm Numbers"). Zone text writes the number (as BIND and Unbound do): the generic form has no prefix.
    SecAlgorithm(u8), "";
    /// RSA/MD5, must not be used (RFC 3110, RFC 4034 appendix A.1.1).
    RSAMD5 = 1, "RSAMD5";
    /// DSA/SHA-1 (RFC 2536).
    DSA = 3, "DSA";
    /// RSA/SHA-1 (RFC 3110).
    RSASHA1 = 5, "RSASHA1";
    /// DSA-NSEC3-SHA1 (RFC 5155 §2).
    DSA_NSEC3_SHA1 = 6, "DSA-NSEC3-SHA1";
    /// RSASHA1-NSEC3-SHA1 (RFC 5155 §2).
    RSASHA1_NSEC3_SHA1 = 7, "RSASHA1-NSEC3-SHA1";
    /// RSA/SHA-256 (RFC 5702 §2).
    RSASHA256 = 8, "RSASHA256";
    /// RSA/SHA-512 (RFC 5702 §3).
    RSASHA512 = 10, "RSASHA512";
    /// GOST R 34.10-2001 (RFC 5933).
    ECC_GOST = 12, "ECC-GOST";
    /// ECDSA curve P-256 with SHA-256 (RFC 6605 §4).
    ECDSAP256SHA256 = 13, "ECDSAP256SHA256";
    /// ECDSA curve P-384 with SHA-384 (RFC 6605 §4).
    ECDSAP384SHA384 = 14, "ECDSAP384SHA384";
    /// Ed25519 (RFC 8080 §3).
    ED25519 = 15, "ED25519";
    /// Ed448 (RFC 8080 §3).
    ED448 = 16, "ED448";
}

code_type! {
    /// Digest algorithm of a DS or CDS record (RFC 4034 §5.1.3, IANA "Delegation Signer (DS) Resource Record
    /// (RR) Type Digest Algorithms"). Zone text writes the number.
    DigestType(u8), "";
    /// SHA-1 (RFC 4034 §5.1.3).
    SHA1 = 1, "SHA-1";
    /// SHA-256 (RFC 4509 §2).
    SHA256 = 2, "SHA-256";
    /// GOST R 34.11-94 (RFC 5933 §4).
    GOST = 3, "GOST";
    /// SHA-384 (RFC 6605 §5).
    SHA384 = 4, "SHA-384";
}

code_type! {
    /// Hash algorithm of NSEC3 and NSEC3PARAM records (RFC 5155 §11). Zone text writes the number.
    Nsec3HashAlgorithm(u8), "";
    /// SHA-1 (RFC 5155 §11).
    SHA1 = 1, "SHA-1";
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
    fn dnssec_types_have_their_registered_values() {
        let types = [
            (RecordType::KX, 36, "KX"),
            (RecordType::DNAME, 39, "DNAME"),
            (RecordType::DS, 43, "DS"),
            (RecordType::RRSIG, 46, "RRSIG"),
            (RecordType::NSEC, 47, "NSEC"),
            (RecordType::DNSKEY, 48, "DNSKEY"),
            (RecordType::NSEC3, 50, "NSEC3"),
            (RecordType::NSEC3PARAM, 51, "NSEC3PARAM"),
            (RecordType::CDS, 59, "CDS"),
            (RecordType::CDNSKEY, 60, "CDNSKEY"),
            (RecordType::NXNAME, 128, "NXNAME"),
        ];
        for (code, value, text) in types {
            assert_eq!(
                (u16::from(code), code.to_string()),
                (value, text.to_owned())
            );
            assert_eq!(text.parse::<RecordType>(), Ok(code));
        }
    }

    #[test]
    fn security_algorithms_have_their_registered_values() {
        let algorithms = [
            (SecAlgorithm::RSAMD5, 1),
            (SecAlgorithm::DSA, 3),
            (SecAlgorithm::RSASHA1, 5),
            (SecAlgorithm::DSA_NSEC3_SHA1, 6),
            (SecAlgorithm::RSASHA1_NSEC3_SHA1, 7),
            (SecAlgorithm::RSASHA256, 8),
            (SecAlgorithm::RSASHA512, 10),
            (SecAlgorithm::ECC_GOST, 12),
            (SecAlgorithm::ECDSAP256SHA256, 13),
            (SecAlgorithm::ECDSAP384SHA384, 14),
            (SecAlgorithm::ED25519, 15),
            (SecAlgorithm::ED448, 16),
        ];
        for (code, value) in algorithms {
            assert_eq!(u8::from(code), value);
        }
        let digests = [
            DigestType::SHA1,
            DigestType::SHA256,
            DigestType::GOST,
            DigestType::SHA384,
        ];
        assert_eq!(digests.map(u8::from), [1, 2, 3, 4]);
        assert_eq!(u8::from(Nsec3HashAlgorithm::SHA1), 1);
    }

    #[test]
    fn dnssec_numbers_have_no_prefix() {
        assert_eq!(SecAlgorithm(250).to_string(), "250");
        assert_eq!("250".parse::<SecAlgorithm>(), Ok(SecAlgorithm(250)));
        assert_eq!(
            "rsasha256".parse::<SecAlgorithm>(),
            Ok(SecAlgorithm::RSASHA256)
        );
        assert_eq!("8".parse::<SecAlgorithm>(), Ok(SecAlgorithm::RSASHA256));
        assert_eq!(DigestType(9).to_string(), "9");
        assert_eq!("2".parse::<DigestType>(), Ok(DigestType::SHA256));
        assert_eq!(
            "1".parse::<Nsec3HashAlgorithm>(),
            Ok(Nsec3HashAlgorithm::SHA1)
        );
        assert!("".parse::<SecAlgorithm>().is_err());
        assert_eq!(
            "x".parse::<DigestType>().map_err(|e| e.to_string()),
            Err("neither a mnemonic nor a number".to_owned())
        );
    }

    #[test]
    fn known_codes_print_their_mnemonic() {
        assert_eq!(RecordType::AAAA.to_string(), "AAAA");
        assert_eq!(Rcode::NXDOMAIN.to_string(), "NXDOMAIN");
        assert_eq!(u16::from(RecordType::HTTPS), 65);
    }
}
