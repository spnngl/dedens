//! The clients of a run, and the checks each of their queries must pass: it ends by its deadline, with a response to
//! its question whose records are an upstream server's data for it (stale or not, EDE 3), SERVFAIL, or a failure of
//! the exchange (no response to any try).

use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use dedens_net::exchange::{Failure, Options};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{
    DecodeError, Flags, Message, Name, Question, Rcode, RecordType, Transport, Violation,
};
use tokio::time::Instant;

use crate::client::{Carrier, Client};
use crate::trace::{Trace, What};
use crate::upstream::Expected;

/// A stub resolver asking the run's resolver, checking what comes back.
#[derive(Debug)]
pub struct Stub {
    client: Client,
    resolver: SocketAddr,
    host: IpAddr,
    trace: Trace,
    expected: Rc<[Expected]>,
    /// How it asks; dig's defaults (D27): three tries, 5 s each.
    pub options: Options,
    /// The UDP payload size its queries announce in EDNS (RFC 6891 §6.2.3): a small one has the resolver truncate
    /// and the stub ask again over TCP. `None` keeps the default of the format.
    pub payload: Option<u16>,
}

/// A response to a query, as the checks saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The response, decoded.
    pub message: Message<'static>,
    /// The response, as received.
    pub wire: Vec<u8>,
    /// The transport it came over: TCP after a truncated response over UDP.
    pub transport: Transport,
    /// From the first query sent to the response.
    pub elapsed: Duration,
    /// Whether it carries EDE 3, Stale Answer (RFC 8914 §4.4): a copy the cache kept past its TTL (RFC 8767).
    pub stale: bool,
}

/// How a query ended, when it passed the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A response to the question, SERVFAIL included.
    Answered(Answer),
    /// No response to any try.
    Failed(Failure),
}

/// A query that broke a rule of the simulation: the run is wrong, not the network.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckError {
    /// The query ended after its deadline.
    #[error("{question:?} ended after {elapsed:?}, past {bound:?}")]
    Late {
        /// The question.
        question: Box<Question<'static>>,
        /// How long it took.
        elapsed: Duration,
        /// The latest it could end: a try more than the tries, for a fallback to TCP.
        bound: Duration,
    },
    /// The response does not decode.
    #[error("the response to {question:?} does not decode: {error}")]
    Undecodable {
        /// The question.
        question: Box<Question<'static>>,
        /// Why.
        error: DecodeError,
    },
    /// The response breaks a rule of the format.
    #[error("the response to {question:?} breaks a rule: {violations:?}")]
    Malformed {
        /// The question.
        question: Box<Question<'static>>,
        /// What it breaks.
        violations: Vec<Violation>,
    },
    /// The response is neither SERVFAIL nor what an upstream server holds for the question.
    #[error("the response to {question:?} is not what an upstream server holds: {got:?}")]
    Unexpected {
        /// The question.
        question: Box<Question<'static>>,
        /// The response.
        got: Box<Message<'static>>,
    },
    /// The response is no response, or is not to the question.
    #[error("the response to {question:?} is not a response to it: {got:?}")]
    NotAnswering {
        /// The question.
        question: Box<Question<'static>>,
        /// The questions of the response.
        got: Vec<Question<'static>>,
    },
}

/// A question in class IN.
///
/// # Panics
///
/// When `name` is not a domain name.
#[must_use]
pub fn question(name: &str, qtype: RecordType) -> Question<'static> {
    Question::new(name.parse::<Name<'static>>().expect("a domain name"), qtype)
}

impl Stub {
    /// A stub on `host` asking `resolver`.
    #[must_use]
    pub fn new(
        client: Client,
        host: IpAddr,
        resolver: SocketAddr,
        trace: Trace,
        expected: Rc<[Expected]>,
    ) -> Self {
        Self {
            client,
            resolver,
            host,
            trace,
            expected,
            options: Options::default(),
            payload: None,
        }
    }

    /// Asks the resolver `question` over `carrier`, and records the query and its end in the trace.
    ///
    /// # Errors
    ///
    /// [`CheckError`] when the query breaks a rule; a failed exchange is an [`Outcome`], not an error: the
    /// network may well lose every packet.
    pub async fn ask(
        &self,
        question: Question<'static>,
        carrier: Carrier,
    ) -> Result<Outcome, CheckError> {
        self.trace.record(
            self.host,
            What::Asked {
                question: question.clone(),
                transport: carrier.into(),
            },
        );
        let mut query = Message::query(0, question.clone());
        if let (Some(payload), Some(edns)) = (self.payload, query.edns.as_mut()) {
            edns.udp_payload = payload;
        }
        let started = Instant::now();
        let result = self
            .client
            .exchange(query, self.resolver, carrier, &self.options)
            .await;
        let elapsed = started.elapsed();
        let bound = self.options.timeout * (u32::from(self.options.tries.get()) + 1);
        if elapsed > bound {
            return Err(CheckError::Late {
                question: Box::new(question),
                elapsed,
                bound,
            });
        }
        match result {
            Ok(response) => {
                let message = self.check(&question, &response.wire)?;
                let stale = message.edns.iter().flat_map(|edns| &edns.options).any(
                    |option| matches!(option, EdnsOption::Ede(ede) if ede.code == InfoCode::STALE_ANSWER),
                );
                self.trace.record(
                    self.host,
                    What::Answered {
                        question,
                        rcode: message.rcode(),
                        answers: message.answer.len(),
                        transport: response.transport,
                    },
                );
                Ok(Outcome::Answered(Answer {
                    message,
                    wire: response.wire,
                    transport: response.transport,
                    elapsed,
                    stale,
                }))
            }
            Err(failure) => {
                self.trace.record(
                    self.host,
                    What::Failed {
                        question,
                        failure: failure.clone(),
                    },
                );
                Ok(Outcome::Failed(failure))
            }
        }
    }

    /// The message of `wire` when it is a response to `question` as the format asks, and SERVFAIL or what an
    /// upstream server holds for it.
    fn check(
        &self,
        question: &Question<'static>,
        wire: &[u8],
    ) -> Result<Message<'static>, CheckError> {
        let decoded = Message::decode(wire).map_err(|error| CheckError::Undecodable {
            question: Box::new(question.clone()),
            error,
        })?;
        if !decoded.violations.is_empty() {
            return Err(CheckError::Malformed {
                question: Box::new(question.clone()),
                violations: decoded.violations,
            });
        }
        let message = decoded.message.into_owned();
        if !message.header.flags.contains(Flags::QR) || message.questions != [question.clone()] {
            return Err(CheckError::NotAnswering {
                question: Box::new(question.clone()),
                got: message.questions,
            });
        }
        let servfail = message.rcode() == Rcode::SERVFAIL && message.answer.is_empty();
        if !servfail
            && !self
                .expected
                .iter()
                .any(|held| held.matches(question, &message))
        {
            return Err(CheckError::Unexpected {
                question: Box::new(question.clone()),
                got: Box::new(message),
            });
        }
        Ok(message)
    }
}
