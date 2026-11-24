//! UPDATE requests (RFC 2136): the zone, prerequisites and changes of a message, each record read into the form
//! it stands for, after the checks of §3.1.1, §3.2.5 and the prescan of §3.4.1.3.

use crate::{Class, Message, Name, Rcode, Record, RecordType, Section, WireRdata};

/// An UPDATE request read whole by [`Update::read`]: a server acts on it knowing each record is well formed and
/// inside the zone (RFC 2136 §3.1 to §3.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update<'a> {
    zone: Name<'a>,
    class: Class,
    prerequisites: Vec<Prerequisite<'a>>,
    changes: Vec<Change<'a>>,
}

/// A prerequisite (RFC 2136 §2.4): what the zone must hold for the update to be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite<'a> {
    /// The `RRset` of the name and type exists (§2.4.1).
    Exists(Name<'a>, RecordType),
    /// The `RRset` of the name and type holds these RDATAs and no other, its TTL aside (§2.4.2); at least one, of
    /// that type, none twice.
    Equals(Name<'a>, RecordType, Vec<WireRdata<'a>>),
    /// No `RRset` of the name and type (§2.4.3).
    Absent(Name<'a>, RecordType),
    /// The name owns a record: an empty non-terminal does not (§2.4.4).
    InUse(Name<'a>),
    /// The name owns no record: an empty non-terminal does not (§2.4.5).
    NotInUse(Name<'a>),
}

/// A change of the update section (RFC 2136 §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change<'a> {
    /// Adds the record to its `RRset` (§2.5.1).
    Add(Record<'a>),
    /// Deletes the `RRset` of the name and type (§2.5.2).
    DeleteRrset(Name<'a>, RecordType),
    /// Deletes every `RRset` of the name (§2.5.3).
    DeleteName(Name<'a>),
    /// Deletes the record of the name with this RDATA, which carries its type (§2.5.4).
    Delete(Name<'a>, WireRdata<'a>),
}

/// Why a message is no UPDATE request to act on (RFC 2136 §3.1.1, §3.2.5, §3.4.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    /// The zone section does not hold one entry (§3.1.1).
    #[error("the zone section holds {0} entries, not one")]
    ZoneCount(usize),
    /// The zone section's entry is not of type SOA (§3.1.1).
    #[error("the zone section asks type {0}, not SOA")]
    ZoneType(RecordType),
    /// A record of the prerequisite section, the answer section on the wire, or of the update section, the
    /// authority section.
    #[error("record {index} of the {section:?} section: {fault}")]
    Record {
        /// [`Section::Answer`] for a prerequisite, [`Section::Authority`] for a change.
        section: Section,
        /// The index of the record in the section.
        index: usize,
        /// What is wrong with it.
        fault: Fault,
    },
}

/// What is wrong with a record of an UPDATE request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Fault {
    /// Its name is not the zone's apex or below (§3.2.5, §3.4.1.3).
    #[error("its name is outside the zone")]
    OutsideZone,
    /// Its TTL is not 0, as every prerequisite's and every deletion's must be.
    #[error("its TTL is not 0")]
    Ttl,
    /// It has RDATA where its class says none.
    #[error("it has RDATA where its class allows none")]
    Rdata,
    /// Its class is not the zone's, ANY or NONE.
    #[error("its class is not the zone's, ANY or NONE")]
    Class,
    /// Its type is not one of data a zone holds, nor ANY where ANY deletes every `RRset` of a name.
    #[error("its type is not one a zone holds")]
    Type,
}

impl UpdateError {
    /// The RCODE that answers it: NOTZONE for a name outside the zone, FORMERR otherwise.
    #[must_use]
    pub const fn rcode(&self) -> Rcode {
        match self {
            Self::Record {
                fault: Fault::OutsideZone,
                ..
            } => Rcode::NOTZONE,
            _ => Rcode::FORMERR,
        }
    }
}

impl<'a> Update<'a> {
    /// Reads the UPDATE request `message`: the zone section has one entry of type SOA (RFC 2136 §3.1.1); the
    /// prerequisites follow §3.2.5 and the changes the prescan of §3.4.1.3, each in turn, the first fault the
    /// error. The value-dependent prerequisites (§2.4.2) are gathered into `RRset`s and come after the others, as
    /// §3.2.5 compares them once the loop is done. The additional section is left aside (§2.6).
    ///
    /// The message is checked whole before any prerequisite is: a fault behind a prerequisite the zone does not
    /// meet is the error, where §3.2.5 would answer with the prerequisite's RCODE first.
    ///
    /// # Errors
    ///
    /// The first [`UpdateError`] met.
    pub fn read(message: Message<'a>) -> Result<Self, UpdateError> {
        let [zone] = <[_; 1]>::try_from(message.questions)
            .map_err(|questions| UpdateError::ZoneCount(questions.len()))?;
        if zone.qtype != RecordType::SOA {
            return Err(UpdateError::ZoneType(zone.qtype));
        }
        let (apex, class) = (zone.name, zone.qclass);
        let mut prerequisites = Vec::new();
        let mut equals: Vec<(Name<'a>, RecordType, Vec<WireRdata<'a>>)> = Vec::new();
        for (index, record) in message.answer.into_iter().enumerate() {
            let fault = |fault| UpdateError::Record {
                section: Section::Answer,
                index,
                fault,
            };
            if record.ttl.get() != 0 {
                return Err(fault(Fault::Ttl));
            }
            if !record.name.is_within(&apex) {
                return Err(fault(Fault::OutsideZone));
            }
            let rtype = record.rtype();
            let empty = record.rdata.wire().is_empty();
            let prerequisite = match (record.class, rtype) {
                (Class::ANY | Class::NONE, _) if !empty => return Err(fault(Fault::Rdata)),
                (Class::ANY, RecordType::ANY) => Prerequisite::InUse(record.name),
                (Class::ANY, _) => Prerequisite::Exists(record.name, rtype),
                (Class::NONE, RecordType::ANY) => Prerequisite::NotInUse(record.name),
                (Class::NONE, _) => Prerequisite::Absent(record.name, rtype),
                (other, _) if other == class => {
                    match equals
                        .iter_mut()
                        .find(|(name, t, _)| *t == rtype && *name == record.name)
                    {
                        Some((_, _, rdatas)) if rdatas.contains(&record.rdata) => {}
                        Some((_, _, rdatas)) => rdatas.push(record.rdata),
                        None => equals.push((record.name, rtype, vec![record.rdata])),
                    }
                    continue;
                }
                _ => return Err(fault(Fault::Class)),
            };
            prerequisites.push(prerequisite);
        }
        prerequisites.extend(
            equals
                .into_iter()
                .map(|(name, rtype, rdatas)| Prerequisite::Equals(name, rtype, rdatas)),
        );
        let changes = (message.authority.into_iter().enumerate())
            .map(|(index, record)| {
                change(record, &apex, class).map_err(|fault| UpdateError::Record {
                    section: Section::Authority,
                    index,
                    fault,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            zone: apex,
            class,
            prerequisites,
            changes,
        })
    }

    /// The zone's apex.
    #[must_use]
    pub const fn zone(&self) -> &Name<'a> {
        &self.zone
    }

    /// The zone's class.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// The prerequisites, the value-dependent ones last.
    #[must_use]
    pub fn prerequisites(&self) -> &[Prerequisite<'a>] {
        &self.prerequisites
    }

    /// The changes, in the order of the message.
    #[must_use]
    pub fn changes(&self) -> &[Change<'a>] {
        &self.changes
    }

    /// The same request, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Update<'static> {
        Update {
            zone: self.zone.into_owned(),
            class: self.class,
            prerequisites: (self.prerequisites.into_iter())
                .map(Prerequisite::into_owned)
                .collect(),
            changes: self.changes.into_iter().map(Change::into_owned).collect(),
        }
    }
}

impl Prerequisite<'_> {
    /// The same prerequisite, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Prerequisite<'static> {
        match self {
            Self::Exists(name, rtype) => Prerequisite::Exists(name.into_owned(), rtype),
            Self::Equals(name, rtype, rdatas) => Prerequisite::Equals(
                name.into_owned(),
                rtype,
                rdatas.into_iter().map(WireRdata::into_owned).collect(),
            ),
            Self::Absent(name, rtype) => Prerequisite::Absent(name.into_owned(), rtype),
            Self::InUse(name) => Prerequisite::InUse(name.into_owned()),
            Self::NotInUse(name) => Prerequisite::NotInUse(name.into_owned()),
        }
    }
}

impl Change<'_> {
    /// The same change, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Change<'static> {
        match self {
            Self::Add(record) => Change::Add(record.into_owned()),
            Self::DeleteRrset(name, rtype) => Change::DeleteRrset(name.into_owned(), rtype),
            Self::DeleteName(name) => Change::DeleteName(name.into_owned()),
            Self::Delete(name, rdata) => Change::Delete(name.into_owned(), rdata.into_owned()),
        }
    }
}

/// The change `record` of the update section of the zone `apex` in `class` stands for, after the prescan of RFC
/// 2136 §3.4.1.3: a type that is no data is refused wherever it would be stored or deleted alone, as Knot's
/// `check_update` (`src/knot/updates/ddns.c`) refuses its metatypes where §3.4.1.3 names ANY, AXFR, MAILA and MAILB.
fn change<'a>(record: Record<'a>, apex: &Name<'_>, class: Class) -> Result<Change<'a>, Fault> {
    if !record.name.is_within(apex) {
        return Err(Fault::OutsideZone);
    }
    let rtype = record.rtype();
    match record.class {
        Class::ANY => {
            if record.ttl.get() != 0 {
                Err(Fault::Ttl)
            } else if !record.rdata.wire().is_empty() {
                Err(Fault::Rdata)
            } else if rtype == RecordType::ANY {
                Ok(Change::DeleteName(record.name))
            } else if rtype.is_data() {
                Ok(Change::DeleteRrset(record.name, rtype))
            } else {
                Err(Fault::Type)
            }
        }
        Class::NONE => {
            if record.ttl.get() != 0 {
                Err(Fault::Ttl)
            } else if rtype.is_data() {
                Ok(Change::Delete(record.name, record.rdata))
            } else {
                Err(Fault::Type)
            }
        }
        other if other == class => {
            if rtype.is_data() {
                Ok(Change::Add(record))
            } else {
                Err(Fault::Type)
            }
        }
        _ => Err(Fault::Class),
    }
}
