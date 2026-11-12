//! Names and addresses from text in the format of `/etc/hosts` (D54).

use std::collections::HashMap;
use std::collections::hash_map::Entry as Slot;
use std::net::{IpAddr, Ipv6Addr};

use dedens_proto::rdata::RData;
use dedens_proto::{Class, MAX_NAME_LEN, Name, Query, Rcode, Record, RecordType, Ttl};
use dedens_server::{Answer, Plugin, Records};

use crate::text::{self, LineError, LineErrorKind};

/// Answers for the names and addresses of a hosts file: A and AAAA records for its names, PTR records for the
/// reverse names of its addresses (RFC 1035 §3.5, RFC 3596 §2.5), with AA set: the data is the server's own.
///
/// A listed name asked for another type, or for a type it has no address of, has no data (NOERROR, no answer,
/// RFC 2308 §2.2), unless `fallthrough` passes such queries to the next stage. Other names and classes go to the
/// next stage.
#[derive(Debug)]
pub struct Hosts {
    names: HashMap<Box<[u8]>, Entry>,
    fallthrough: bool,
}

/// The records of a name.
#[derive(Debug, Default)]
struct Entry {
    a: Option<Records>,
    aaaa: Option<Records>,
    ptr: Option<Records>,
}

/// A name's records while reading.
#[derive(Debug)]
struct Pending {
    name: Name<'static>,
    /// The last line that added an address, or the name's first: the one a name with too many records is blamed on.
    line: usize,
    a: Vec<RData<'static>>,
    aaaa: Vec<RData<'static>>,
    ptr: Option<RData<'static>>,
}

impl Hosts {
    /// The hosts of `text`, in the format of `/etc/hosts`: on each line an address, then its canonical name and
    /// any aliases, `#` starting a comment. All names get the address; the canonical name is the PTR record of
    /// its first line. Lines of an IPv6 address with a zone (`fe80::1%lo0`) are left out: a zone means nothing
    /// beyond the host. Every record has `ttl`.
    ///
    /// # Errors
    ///
    /// [`LineError`] for a line whose address or names cannot be read, or the line adding an address to a name
    /// already holding more than a message carries.
    pub fn new(text: &str, ttl: Ttl, fallthrough: bool) -> Result<Self, LineError> {
        let mut pending: HashMap<Box<[u8]>, Pending> = HashMap::new();
        let mut buf = [0; MAX_NAME_LEN];
        for (line, mut fields) in text::lines(text) {
            let field = fields.next().unwrap_or_default();
            if field
                .split_once('%')
                .is_some_and(|(address, _)| address.parse::<Ipv6Addr>().is_ok())
            {
                continue;
            }
            let address: IpAddr = field.parse().map_err(|_| LineError {
                line,
                kind: LineErrorKind::Address(field.to_owned()),
            })?;
            let mut names = fields.peekable();
            if names.peek().is_none() {
                return Err(LineError {
                    line,
                    kind: LineErrorKind::NoName,
                });
            }
            for (index, field) in names.enumerate() {
                let name = text::name(line, field)?;
                if index == 0 {
                    let reverse = Name::reverse(address);
                    let at = pending_of(&mut pending, &reverse, line, &mut buf);
                    at.ptr.get_or_insert(RData::Ptr(name.clone()));
                }
                let at = pending_of(&mut pending, &name, line, &mut buf);
                let (list, data) = match address {
                    IpAddr::V4(v4) => (&mut at.a, RData::A(v4)),
                    IpAddr::V6(v6) => (&mut at.aaaa, RData::Aaaa(v6)),
                };
                if !list.contains(&data) {
                    list.push(data);
                    at.line = line;
                }
            }
        }
        let names = pending
            .into_iter()
            .map(|(key, pending)| Ok((key, pending.build(ttl)?)))
            .collect::<Result<_, LineError>>()?;
        Ok(Self { names, fallthrough })
    }
}

/// The pending records of `name`, added at `line` if new.
fn pending_of<'p>(
    pending: &'p mut HashMap<Box<[u8]>, Pending>,
    name: &Name<'static>,
    line: usize,
    buf: &mut [u8; MAX_NAME_LEN],
) -> &'p mut Pending {
    match pending.entry(text::key(name, buf).as_bytes().into()) {
        Slot::Occupied(slot) => slot.into_mut(),
        Slot::Vacant(slot) => slot.insert(Pending {
            name: name.clone(),
            line,
            a: Vec::new(),
            aaaa: Vec::new(),
            ptr: None,
        }),
    }
}

impl Pending {
    /// The records, each type's in one [`Records`].
    fn build(self, ttl: Ttl) -> Result<Entry, LineError> {
        let records = |data: &[RData<'static>]| -> Result<Option<Records>, LineError> {
            if data.is_empty() {
                return Ok(None);
            }
            let records: Vec<_> = data
                .iter()
                .map(|data| Record::new(self.name.clone(), Class::IN, ttl, data))
                .collect();
            Records::new(&self.name, &records)
                .map(Some)
                .map_err(|_| LineError {
                    line: self.line,
                    kind: LineErrorKind::TooMany(self.name.to_string()),
                })
        };
        Ok(Entry {
            a: records(&self.a)?,
            aaaa: records(&self.aaaa)?,
            ptr: records(self.ptr.as_slice())?,
        })
    }
}

impl Plugin for Hosts {
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
        let question = query.question()?;
        if question.qclass != Class::IN {
            return None;
        }
        let mut buf = [0; MAX_NAME_LEN];
        let entry = self
            .names
            .get(text::key(&question.name, &mut buf).as_bytes())?;
        let records = match question.qtype {
            RecordType::A => entry.a.as_ref(),
            RecordType::AAAA => entry.aaaa.as_ref(),
            RecordType::PTR => entry.ptr.as_ref(),
            _ => None,
        };
        if records.is_none() && self.fallthrough {
            return None;
        }
        Some(Answer {
            rcode: Rcode::NOERROR,
            records,
            authoritative: true,
            error: None,
        })
    }
}
