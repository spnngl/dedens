//! The clients of a run, and the checks each of their queries must pass: it ends by its deadline, with a response to
//! its question that the [`oracle`](crate::oracle) allows (an upstream server's data, a stale copy of it, a defined
//! failure), a failure of the exchange (no response to any try), or the I/O error the real client would return.

use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use dedens_net::client::ClientError;
use dedens_net::exchange::{Failure, Options, SPARE_IDS};
use dedens_proto::edns::EdnsFlags;
use dedens_proto::{DecodeError, Flags, Message, Name, Question, RecordType, Transport, Violation};
use tokio::time::Instant;

use crate::client::{Carrier, Client};
use crate::oracle::{Expected, Rules, is_stale, judge};
use crate::trace::{Trace, What};

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
    /// and the stub ask again over TCP, which exercises the client's fallback. `None` keeps the default of the
    /// format.
    pub payload: Option<u16>,
    /// What it accepts besides the data of the upstream servers; with [`Rules::dnssec`] its queries set DO.
    pub rules: Rules,
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
#[derive(Debug)]
pub enum Outcome {
    /// A response to the question, SERVFAIL included when the rules allow it.
    Answered(Answer),
    /// No response to any try.
    Failed(Failure),
    /// An error of the socket or the connection, as the real client returns it: a connection refused or reset.
    Io(ClientError),
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
        /// The latest it could end: a try more than the tries for each fallback.
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
    /// The response is not what the oracle allows.
    #[error("the response to {question:?} is not allowed: {why}: {got:?}")]
    Unexpected {
        /// The question.
        question: Box<Question<'static>>,
        /// The rule it breaks.
        why: String,
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
    /// The query ended without a response where the path is up ([`Stub::expect`]).
    #[error("{question:?} got no response: {outcome}")]
    Dead {
        /// The question.
        question: Box<Question<'static>>,
        /// How it ended.
        outcome: String,
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

/// The latest a query with `options` may end: each try takes the timeout, and each fallback (TCP after TC, no EDNS,
/// a fresh cookie) sends one more.
#[must_use]
pub fn bound(options: &Options) -> Duration {
    let spare = u32::try_from(SPARE_IDS).unwrap_or(u32::MAX);
    options.timeout * (u32::from(options.tries.get()) + spare)
}

/// Whether a query that took `elapsed` ended after `bound`.
fn late(elapsed: Duration, bound: Duration) -> bool {
    elapsed > bound
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
            rules: Rules::default(),
        }
    }

    /// The query for `question` as the stub's settings shape it: its EDNS size, and DO when it asks for DNSSEC
    /// records.
    fn query(&self, question: Question<'static>) -> Message<'static> {
        let mut query = Message::query(0, question);
        if let Some(edns) = query.edns.as_mut() {
            if let Some(payload) = self.payload {
                edns.udp_payload = payload;
            }
            if self.rules.dnssec {
                edns.flags = EdnsFlags::DO;
            }
        }
        query
    }

    /// Asks the resolver `question` over `carrier`, and records the query and its end in the trace.
    ///
    /// # Errors
    ///
    /// [`CheckError`] when the query breaks a rule; a failed exchange is an [`Outcome`], not an error: the
    /// network may well lose every packet. So is an error of the socket or the connection ([`Outcome::Io`], any
    /// kind): a scenario that must have none checks for it, as [`Stub::expect`] does.
    pub async fn ask(
        &self,
        question: Question<'static>,
        carrier: Carrier,
    ) -> Result<Outcome, CheckError> {
        let query = self.query(question);
        self.ask_by(&self.rules, query, self.resolver, carrier)
            .await
    }

    /// [`Stub::ask`] with a query of the scenario's own making (a cookie, EDNS options, flags) to `server`, which
    /// need not be the resolver: a port nobody listens on, say. The client sets its ID; the stub's EDNS size and DO
    /// are not applied.
    ///
    /// # Errors
    ///
    /// As [`Stub::ask`].
    ///
    /// # Panics
    ///
    /// When `query` has no question.
    pub async fn ask_query(
        &self,
        query: Message<'static>,
        server: SocketAddr,
        carrier: Carrier,
    ) -> Result<Outcome, CheckError> {
        self.ask_by(&self.rules, query, server, carrier).await
    }

    /// [`Stub::ask_query`] under `rules`.
    async fn ask_by(
        &self,
        rules: &Rules,
        query: Message<'static>,
        server: SocketAddr,
        carrier: Carrier,
    ) -> Result<Outcome, CheckError> {
        let question = query
            .questions
            .first()
            .cloned()
            .expect("a query with a question");
        self.trace.record(
            self.host,
            What::Asked {
                question: question.clone(),
                transport: carrier.into(),
            },
        );
        let started = Instant::now();
        let result = self
            .client
            .exchange(query, server, carrier, &self.options)
            .await;
        let elapsed = started.elapsed();
        let bound = bound(&self.options);
        if late(elapsed, bound) {
            return Err(CheckError::Late {
                question: Box::new(question),
                elapsed,
                bound,
            });
        }
        match result {
            Ok(response) => {
                let message = check(&self.expected, rules, &question, &response.wire)?;
                // Nothing is cut over TCP or TLS (RFC 1035 §4.2.2, RFC 7858 §3.3): a client that got TC there
                // has nowhere to go.
                if matches!(response.transport, Transport::Tcp | Transport::Tls)
                    && message.header.flags.contains(Flags::TC)
                {
                    return Err(CheckError::Unexpected {
                        question: Box::new(question),
                        why: format!("TC over {:?}", response.transport),
                        got: Box::new(message),
                    });
                }
                let stale = is_stale(&message);
                self.trace.record(
                    self.host,
                    What::Answered {
                        question,
                        rcode: message.rcode(),
                        answers: message.answer.len(),
                        transport: response.transport,
                        len: response.wire.len(),
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
            Err(ClientError::Exchange(failure)) => {
                self.trace.record(
                    self.host,
                    What::Failed {
                        question,
                        failure: failure.clone(),
                    },
                );
                Ok(Outcome::Failed(failure))
            }
            Err(error) => {
                self.trace.record(
                    self.host,
                    What::Errored {
                        question,
                        error: error.to_string(),
                    },
                );
                Ok(Outcome::Io(error))
            }
        }
    }

    /// Asks `question` where the path to an upstream server is up: it must end in a response that is not a
    /// failure of the resolver's.
    ///
    /// # Errors
    ///
    /// [`CheckError`] when the query breaks a rule, SERVFAIL included, or ends with no response.
    pub async fn expect(
        &self,
        question: Question<'static>,
        carrier: Carrier,
    ) -> Result<Answer, CheckError> {
        let live = Rules {
            live: true,
            ..self.rules.clone()
        };
        let query = self.query(question.clone());
        match self.ask_by(&live, query, self.resolver, carrier).await? {
            Outcome::Answered(answer) => Ok(answer),
            other => Err(CheckError::Dead {
                question: Box::new(question),
                outcome: format!("{other:?}"),
            }),
        }
    }
}

/// The message of `wire` when it is a response to `question` as the format asks, and the oracle allows it.
fn check(
    expected: &[Expected],
    rules: &Rules,
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
    match judge(expected, rules, question, &message) {
        Ok(()) => Ok(message),
        Err(why) => Err(CheckError::Unexpected {
            question: Box::new(question.clone()),
            why,
            got: Box::new(message),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU8;

    use dedens_proto::Rcode;

    use super::*;
    use crate::upstream::captured;

    #[test]
    fn a_query_is_late_after_its_bound_only() {
        let bound = Duration::from_secs(3);
        assert!(!late(Duration::from_millis(2999), bound));
        assert!(!late(bound, bound));
        assert!(late(bound + Duration::from_nanos(1), bound));
    }

    fn wire_of(message: &Message<'static>) -> Vec<u8> {
        let mut out = vec![0; 65535];
        let len = message.encode(&mut out).expect("encodes");
        out.truncate(len);
        out
    }

    fn held() -> (Vec<Expected>, Message<'static>) {
        let message = Message::decode(&captured("a"))
            .expect("a captured response decodes")
            .message
            .into_owned();
        (vec![Expected::of(&message)], message)
    }

    fn asked() -> Question<'static> {
        question("example.com", RecordType::A)
    }

    #[test]
    fn the_response_the_oracle_allows_passes() {
        let (expected, message) = held();
        let got = check(&expected, &Rules::default(), &asked(), &captured("a"));
        assert_eq!(got.expect("passes"), message);
    }

    #[test]
    fn what_the_oracle_refuses_fails() {
        let (expected, mut message) = held();
        message.answer.pop();
        let got = check(&expected, &Rules::default(), &asked(), &wire_of(&message));
        assert!(matches!(got, Err(CheckError::Unexpected { .. })), "{got:?}");
    }

    #[test]
    fn a_response_to_another_question_is_not_an_answer() {
        let (expected, message) = held();
        let other = question("other.example", RecordType::A);
        let got = check(&expected, &Rules::default(), &other, &wire_of(&message));
        assert!(
            matches!(got, Err(CheckError::NotAnswering { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn a_query_is_not_an_answer() {
        let (expected, mut message) = held();
        message.header.flags = Flags::default();
        let got = check(&expected, &Rules::default(), &asked(), &wire_of(&message));
        assert!(
            matches!(got, Err(CheckError::NotAnswering { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn bytes_that_do_not_decode_fail() {
        let (expected, _) = held();
        let got = check(&expected, &Rules::default(), &asked(), &[1, 2, 3]);
        assert!(
            matches!(got, Err(CheckError::Undecodable { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn the_rules_of_the_scenario_reach_the_oracle() {
        let (expected, mut message) = held();
        message.answer.clear();
        message.set_rcode(Rcode::SERVFAIL).expect("a code");
        let wire = wire_of(&message);
        assert!(check(&expected, &Rules::default(), &asked(), &wire).is_ok());
        let live = Rules {
            live: true,
            ..Rules::default()
        };
        assert!(check(&expected, &live, &asked(), &wire).is_err());
    }

    #[test]
    fn a_query_ends_within_a_try_for_each_fallback() {
        let mut options = Options::default();
        options.timeout = Duration::from_secs(2);
        options.tries = NonZeroU8::MIN;
        assert_eq!(bound(&options), Duration::from_secs(2 * (1 + 4)));
        options.tries = NonZeroU8::new(3).expect("non-zero");
        assert_eq!(bound(&options), Duration::from_secs(2 * (3 + 4)));
    }
}
