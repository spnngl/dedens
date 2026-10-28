//! Names refused to clients, and their subdomains (D54).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dedens_proto::edns::InfoCode;
use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{Class, Name, Query, RData, Rcode, Record, RecordType, Ttl};
use dedens_server::{Answer, Plugin, Records};

use crate::text::{self, LineError};

/// The reply to a blocked query, each with the Extended DNS Error Blocked (RFC 8914 §4.16) for clients sending an
/// OPT record, and AA clear: the answer is a policy, not data the server holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(rename_all = "lowercase")
)]
#[non_exhaustive]
pub enum Action {
    /// The name does not exist (RFC 1035 §4.1.1, RFC 8020).
    #[default]
    Nxdomain,
    /// The name has no data of the type (RFC 2308 §2.2).
    Nodata,
    /// The server refuses to answer (RFC 1035 §4.1.1).
    Refused,
    /// The unspecified address, `0.0.0.0` or `::`, to A and AAAA queries; no data to other types.
    Null,
}

/// Names blocked with their subdomains, matched without regard to case (RFC 4343 §3); other names, and other
/// classes than IN, go to the next stage.
#[derive(Debug)]
pub struct Blocklist {
    names: HashSet<Box<[u8]>>,
    action: Action,
    null_a: Records,
    null_aaaa: Records,
}

impl Blocklist {
    /// The names of `text`: one per line, or lines in the format of `/etc/hosts` (`0.0.0.0 ads.example`), `#`
    /// starting a comment. Of the latter, only lines of the addresses blocklists use count, `0.0.0.0`, `::`,
    /// `127.0.0.1` and `::1`, and of their names neither those of one label nor those starting with
    /// `localhost`: such files start with the entries of their host (`127.0.0.1 localhost`, `::1
    /// ip6-loopback`). `ttl` is that of the records of [`Action::Null`].
    ///
    /// # Errors
    ///
    /// [`LineError`] for a line with a field that is not a domain name.
    ///
    /// # Panics
    ///
    /// Never: the records of [`Action::Null`] are one address each.
    pub fn new(text: &str, action: Action, ttl: Ttl) -> Result<Self, LineError> {
        let mut names = HashSet::new();
        let mut buf = [0; MAX_NAME_LEN];
        for (line, mut fields) in text::lines(text) {
            let first = fields.next().unwrap_or_default();
            let hosts = match first.parse::<IpAddr>() {
                Ok(address) if address.is_unspecified() || address.is_loopback() => true,
                Ok(_) => continue,
                Err(_) if first.contains('%') => continue,
                Err(_) => {
                    let name = text::name(line, first)?;
                    names.insert(text::key(&name, &mut buf).into());
                    false
                }
            };
            for field in fields {
                let name = text::name(line, field)?;
                let local = name.label_count() < 2
                    || name
                        .labels()
                        .next()
                        .is_some_and(|label| label.eq_ignore_ascii_case(b"localhost"));
                if !(hosts && local) {
                    names.insert(text::key(&name, &mut buf).into());
                }
            }
        }
        // One record owned by the question's name: its owner is a pointer to the question, whatever its name.
        let null = |data: RData<'static>| {
            let name = Name::from_labels([&b"blocked"[..]]).expect("a name of one short label");
            let record = Record::new(name.clone(), Class::IN, ttl, &data);
            Records::new(&name, &[record]).expect("one address record fits a message")
        };
        Ok(Self {
            names,
            action,
            null_a: null(RData::A(Ipv4Addr::UNSPECIFIED)),
            null_aaaa: null(RData::Aaaa(Ipv6Addr::UNSPECIFIED)),
        })
    }

    /// Whether the name `key` or one of its parents is listed.
    fn blocks(&self, key: &[u8]) -> bool {
        let mut at = 0;
        loop {
            let Some(suffix) = key.get(at..) else {
                return false;
            };
            if self.names.contains(suffix) {
                return true;
            }
            match suffix.first() {
                Some(&len) if len > 0 => at += 1 + usize::from(len),
                _ => return false,
            }
        }
    }
}

impl Plugin for Blocklist {
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
        let question = query.question()?;
        let mut buf = [0; MAX_NAME_LEN];
        if question.qclass != Class::IN || !self.blocks(text::key(&question.name, &mut buf)) {
            return None;
        }
        let (rcode, records) = match self.action {
            Action::Nxdomain => (Rcode::NXDOMAIN, None),
            Action::Nodata => (Rcode::NOERROR, None),
            Action::Refused => (Rcode::REFUSED, None),
            Action::Null => (
                Rcode::NOERROR,
                match question.qtype {
                    RecordType::A => Some(&self.null_a),
                    RecordType::AAAA => Some(&self.null_aaaa),
                    _ => None,
                },
            ),
        };
        Some(Answer {
            rcode,
            records,
            authoritative: false,
            error: Some(InfoCode::BLOCKED),
        })
    }
}
