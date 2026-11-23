//! Authoritative zones (D204): the content of a zone, loaded from zone text and checked.
//!
//! [`Zone::load`] reads zone text with [`dedens_proto::ZoneReader`], follows `$INCLUDE` through a callback of the
//! caller, and returns the [`Zone`] if every check passes (RFC 1035 §5.2, RFC 2181
//! §5, §10.1, RFC 6672 §2.3, §2.4), or the [`Report`] of every error with its file, line and column. A [`Zone`]
//! never changes: a change loads a new one, [`Zone::apply`] from a [`Changeset`], which [`Zone::diff`] finds
//! between two versions. The [`journal`] keeps changesets in a file (D207): the one place the crate does file I/O.

mod answer;
mod builder;
mod changeset;
mod denial;
mod difference;
mod error;
pub mod journal;
mod limits;
mod load;
mod node;
mod reply;
mod zone;

pub use answer::{Answer, End, Entry, Link, MAX_CHAIN, Match};
pub use changeset::{Changeset, ChangesetError};
pub use error::{Bound, ErrorKind, Place, Report, Warning, WarningKind, ZoneError};
pub use limits::Limits;
pub use load::{Include, Loaded, Source};
pub use node::{Kind, Node, RrSet};
pub use reply::{Dnssec, Glue};
pub use zone::Zone;
