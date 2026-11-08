//! The server's query pipeline (D23), sans-IO: bytes in, bytes out, and upstream queries handed to the caller to
//! send, so tests drive every reply without a socket.
//!
//! ```
//! # use dedens_proto::{Message, Name, Question, RecordType, Rcode, Transport};
//! # use dedens_server::{Forward, Pipeline, Stage, Step};
//! # use std::net::Ipv4Addr;
//! let upstream = "192.0.2.53:53".parse()?;
//! let pipeline = Pipeline::new(vec![Stage::Forward(Forward::new([upstream]).expect("one server"))]);
//! let query = Message::query(7, Question::new(Name::root(), RecordType::NS)).to_vec()?;
//! let mut out = [0; 65535];
//! let Step::Upstream(ask) = pipeline.query(&query, Transport::Udp, Ipv4Addr::LOCALHOST.into(), 0, &mut out) else { unreachable!() };
//! assert_eq!(ask.server().addr, upstream);
//! // Nothing came back from the only server.
//! let Step::Reply(len) = pipeline.receive(ask, None, 0, &mut out) else { unreachable!() };
//! let reply = Message::decode(&out[..len])?.message;
//! assert_eq!((reply.header.id, reply.rcode()), (7, Rcode::SERVFAIL));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod access;
mod budget;
mod cache;
mod cookie;
mod forward;
mod metrics;
mod pipeline;
mod plugin;
mod reply;
mod rrl;
mod validate;

pub use access::{Access, Denial, Network, NetworkError};
pub use budget::{Budget, BudgetError, Budgets, MAX_BUDGET, Slot};
pub use cookie::{Cookies, Secret, SecretError, Secrets, Standing};
pub use forward::{Forward, Server, Via};
pub use pipeline::{Pipeline, Stage, Step, Upstream};
pub use plugin::{Answer, Plugin, Records, Reviewer};
pub use rrl::{Admission, MAX_BURST, Rate, RateLimit, RateLimitConfig, RateLimitError};
pub use validate::{Allowance, Clock, DEFAULT_SHARE, Validating};
