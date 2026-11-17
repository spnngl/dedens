//! What a resolver starts from at the top of the tree (D126): IANA's root hints, the configured list of root servers
//! a resolver primes from (RFC 8109 §2, the SBELT of RFC 1034 §5.3.3), and its TLD list, `tlds.json`, the name
//! servers and DS records of each top-level domain.
//!
//! Both are bundled, compiled in as IANA's files (`just roots` refreshes them): [`RootHints::bundled`],
//! [`Tlds::bundled`]. A fresh copy, downloaded by the caller, reads into the same type: [`RootHints::read`],
//! [`Tlds::read`]. No I/O here.
//!
//! The DS records of `tlds.json` are hints: the file is not signed, only HTTPS vouches for it, so a validator checks
//! them against the root zone's signed DS records before trusting them (D126).

mod hints;
mod server;
mod tlds;

pub use hints::{HintsError, RootHints};
pub use server::Server;
pub use tlds::{Kind, Status, Tld, Tlds, TldsError};
