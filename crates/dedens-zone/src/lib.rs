//! Authoritative zones (D204): the content of a zone, loaded from zone text and checked.
//!
//! [`Zone::load`] reads zone text with [`dedens_proto::ZoneReader`], follows `$INCLUDE` through a callback of the
//! caller (the only I/O of the crate), and returns the [`Zone`] if every check passes (RFC 1035 §5.2, RFC 2181
//! §5, §10.1, RFC 6672 §2.3, §2.4), or the [`Report`] of every error with its file, line and column. A [`Zone`]
//! never changes: a change loads a new one.

mod builder;
mod changeset;
mod difference;
mod error;
mod limits;
mod load;
mod node;
mod zone;

pub use changeset::{Changeset, ChangesetError};
pub use error::{Bound, ErrorKind, Place, Report, Warning, WarningKind, ZoneError};
pub use limits::Limits;
pub use load::{Include, Loaded, Source};
pub use node::{Kind, Node, RrSet};
pub use zone::Zone;
