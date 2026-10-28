//! Plugin stages of the server (D54), sans-IO: each is built from text its caller read, and answers from what it
//! holds without allocating.
//!
//! ```
//! # use dedens_plugins::Hosts;
//! # use dedens_proto::{Message, Name, Question, RecordType, Rcode, Ttl};
//! # use dedens_server::{Pipeline, Stage, Step, Transport};
//! let hosts = Hosts::new("192.0.2.1 printer.lan", Ttl::from_wire(3600), false)?;
//! let pipeline = Pipeline::new(vec![Stage::Plugin(Box::new(hosts))]);
//! let name: Name<'static> = "printer.lan.".parse()?;
//! let query = Message::query(7, Question::new(name, RecordType::A)).to_vec()?;
//! let mut out = [0; 512];
//! let Step::Reply(len) = pipeline.query(&query, Transport::Udp, 0, &mut out) else { unreachable!() };
//! let reply = Message::decode(&out[..len])?.message;
//! assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NOERROR, 1));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod hosts;
mod text;

pub use hosts::Hosts;
pub use text::{LineError, LineErrorKind};
