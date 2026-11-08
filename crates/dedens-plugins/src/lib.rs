//! Plugin stages of the server (D54), sans-IO: each is built from text its caller read, and answers from what it
//! holds without allocating.
//!
//! ```
//! # use dedens_plugins::Hosts;
//! # use dedens_proto::{Message, Name, Question, Rcode, RecordType, Transport, Ttl};
//! # use dedens_server::{Pipeline, Stage, Step};
//! # use std::net::Ipv4Addr;
//! let hosts = Hosts::new("192.0.2.1 printer.lan", Ttl::from_wire(3600), false)?;
//! let pipeline = Pipeline::new(vec![Stage::Plugin(Box::new(hosts))]);
//! let name: Name<'static> = "printer.lan.".parse()?;
//! let query = Message::query(7, Question::new(name, RecordType::A)).to_vec()?;
//! let mut out = [0; 512];
//! let Step::Reply(len) = pipeline.query(&query, Transport::Udp, Ipv4Addr::LOCALHOST.into(), 0, &mut out) else { unreachable!() };
//! let reply = Message::decode(&out[..len])?.message;
//! assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NOERROR, 1));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod blocklist;
mod hosts;
mod text;

pub use blocklist::{
    Action, Blocklist, List, ListError, Lists, MAX_HOPS, Merged, Names, Origin, Read, Tlds,
};
pub use hosts::Hosts;
pub use text::{LineError, LineErrorKind};
