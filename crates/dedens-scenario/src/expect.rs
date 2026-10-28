//! What a response must hold (D34): rcode, flags, and the records of each section.

use dedens_proto::text::{Entry, TextError, TextErrorKind, ZoneReader};
use dedens_proto::{Flags, Message, Name, Rcode, Record, Ttl};
use serde::Deserialize;

/// The expectations of a query; each one left out is not checked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    /// The response code, extended by EDNS (RFC 6891 §6.1.3).
    #[serde(default, deserialize_with = "crate::parsed_some")]
    pub rcode: Option<Rcode>,
    /// Header flags that must be set, by their names in dig: `qr`, `aa`, `tc`, `rd`, `ra`, `ad`, `cd`.
    #[serde(default, deserialize_with = "flag_names")]
    pub flags: Flags,
    /// The answer section, as a set.
    pub answer: Option<Vec<Expected>>,
    /// The authority section, as a set.
    pub authority: Option<Vec<Expected>>,
    /// The additional section without the OPT record, as a set.
    pub additional: Option<Vec<Expected>>,
}

impl Expect {
    /// What `response` breaks of these expectations, in words; empty when it meets them all.
    #[must_use]
    pub fn check(&self, response: &Message<'_>) -> Vec<String> {
        let mut failures = Vec::new();
        if let Some(rcode) = self.rcode
            && response.rcode() != rcode
        {
            failures.push(format!("rcode {} instead of {rcode}", response.rcode()));
        }
        for flag in self.flags.without(response.header.flags).names() {
            failures.push(format!("flag {flag} not set"));
        }
        for (section, expected, records) in [
            ("answer", &self.answer, &response.answer),
            ("authority", &self.authority, &response.authority),
            ("additional", &self.additional, &response.additional),
        ] {
            let Some(expected) = expected else {
                continue;
            };
            for missing in expected
                .iter()
                .filter(|e| !records.iter().any(|r| e.matches(r)))
            {
                failures.push(format!("{section}: missing {}", missing.line));
            }
            for extra in records
                .iter()
                .filter(|r| !expected.iter().any(|e| e.matches(r)))
            {
                failures.push(format!("{section}: unexpected {extra}"));
            }
        }
        failures
    }
}

/// An expected record: one line of presentation format (RFC 1035 §5.1), names absolute, the TTL compared only
/// when written.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Expected {
    line: String,
    record: Record<'static>,
    ttl: bool,
}

impl Expected {
    /// Whether `record` is this one.
    #[must_use]
    pub fn matches(&self, record: &Record<'_>) -> bool {
        let expected = &self.record;
        expected.name == record.name
            && expected.class == record.class
            && expected.rdata == record.rdata
            && (!self.ttl || expected.ttl == record.ttl)
    }
}

impl TryFrom<String> for Expected {
    type Error = TextError;

    fn try_from(line: String) -> Result<Self, TextError> {
        let (record, ttl) = match line.parse::<Record<'static>>() {
            Ok(record) => (record, true),
            Err(error) if error.kind == TextErrorKind::NoTtl => {
                let mut reader =
                    ZoneReader::new(line.as_bytes(), Some(Name::root())).with_ttl(Ttl::ZERO);
                match reader.next() {
                    Some(Ok(Entry::Record(decoded))) if decoded.invalid_rdata.is_none() => {
                        (decoded.record, false)
                    }
                    Some(Err(error)) => return Err(error),
                    _ => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        Ok(Self { line, record, ttl })
    }
}

/// Reads a list of flag names into one set.
fn flag_names<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Flags, D::Error> {
    const NAMES: [(&str, Flags); 7] = [
        ("qr", Flags::QR),
        ("aa", Flags::AA),
        ("tc", Flags::TC),
        ("rd", Flags::RD),
        ("ra", Flags::RA),
        ("ad", Flags::AD),
        ("cd", Flags::CD),
    ];
    let names = Vec::<String>::deserialize(deserializer)?;
    names.iter().try_fold(Flags::NONE, |flags, name| {
        let (_, flag) = NAMES
            .iter()
            .find(|(known, _)| name.eq_ignore_ascii_case(known))
            .ok_or_else(|| serde::de::Error::custom(format!("unknown flag {name}")))?;
        Ok(flags.with(*flag))
    })
}
