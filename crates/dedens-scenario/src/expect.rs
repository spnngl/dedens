//! What a response must hold (D34): rcode, flags, and the records of each section.

use dedens_proto::text::{TextError, TextErrorKind};
use dedens_proto::{Flags, Message, Rcode, Record};
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
    /// The answer section, in any order.
    pub answer: Option<Vec<Expected>>,
    /// The authority section, in any order.
    pub authority: Option<Vec<Expected>>,
    /// The additional section without the OPT record, in any order.
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
            // Each record meets one expected at most, so a record expected twice must come twice.
            let mut met = vec![false; records.len()];
            for e in expected {
                let found = (0..records.len()).find(|&i| !met[i] && e.matches(&records[i]));
                match found {
                    Some(i) => met[i] = true,
                    None => failures.push(format!("{section}: missing {}", e.line)),
                }
            }
            for (record, _) in records.iter().zip(&met).filter(|(_, met)| !**met) {
                failures.push(format!("{section}: unexpected {record}"));
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
            // Read again with a TTL after the owner, which the comparison then ignores.
            Err(error) if error.kind == TextErrorKind::NoTtl => {
                let (owner, rest) = line.trim_start().split_once([' ', '\t']).ok_or(error)?;
                (format!("{owner} 0 {rest}").parse()?, false)
            }
            Err(error) => return Err(error),
        };
        Ok(Self { line, record, ttl })
    }
}

/// Reads a list of flag names into one set.
fn flag_names<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Flags, D::Error> {
    let names = Vec::<String>::deserialize(deserializer)?;
    names.iter().try_fold(Flags::NONE, |flags, name| {
        let flag = Flags::from_name(name)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown flag {name}")))?;
        Ok(flags.with(flag))
    })
}
