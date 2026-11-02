//! An upstream server: answers from responses captured from real servers, with the query's ID, over UDP and TCP.
//!
//! Left out: the zone data of a real server; a scenario that needs it adds a pipeline with a local-data stage here.

use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;

use dedens_proto::{Flags, Message, Question, Rcode, Record, Transport};
use turmoil::net::{TcpStream, UdpSocket};

use crate::attacker::{Attacker, Injection, Seen};
use crate::framing;
use crate::port::{Arrival, Port};
use crate::trace::{Trace, What};

/// The responses an upstream server holds, each for a question, and the attacker on its host, if any.
#[derive(Debug, Default, Clone)]
pub struct Answers {
    entries: Vec<Entry>,
    attacker: Option<Attacker>,
}

/// What a client may get for a question: the data of an upstream server, which an answer must equal (TTLs
/// aside), served from the cache or not, stale or not.
#[derive(Debug, Clone)]
pub struct Expected {
    question: Question<'static>,
    rcode: Rcode,
    answer: Vec<Record<'static>>,
}

impl Expected {
    /// Whether `message` is a response to the question with these records and this response code.
    #[must_use]
    pub fn matches(&self, question: &Question<'_>, message: &Message<'_>) -> bool {
        // The TTLs are not compared: a cache counts them down.
        let same = |a: &Record<'_>, b: &Record<'_>| {
            a.name == b.name && a.class == b.class && a.rdata == b.rdata
        };
        self.question == *question
            && self.rcode == message.rcode()
            && self.answer.len() == message.answer.len()
            && self
                .answer
                .iter()
                .all(|want| message.answer.iter().any(|got| same(want, got)))
            && message
                .answer
                .iter()
                .all(|got| self.answer.iter().any(|want| same(want, got)))
    }
}

#[derive(Debug, Clone)]
struct Entry {
    question: Question<'static>,
    udp: Vec<u8>,
    tcp: Vec<u8>,
}

/// A response captured from a real server, in `crates/dedens-proto/tests/testdata`.
fn captured(case: &str) -> Vec<u8> {
    let path = format!(
        "{}/../dedens-proto/tests/testdata/{case}.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("a captured response")
}

/// The question of a response.
fn question(wire: &[u8]) -> Question<'static> {
    Message::decode(wire)
        .expect("a captured response decodes")
        .message
        .questions
        .swap_remove(0)
        .into_owned()
}

impl Answers {
    /// No responses: the server answers nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers the question of the captured response `case` with it, over UDP and TCP.
    ///
    /// # Panics
    ///
    /// When the file is missing or is not a response with a question.
    #[must_use]
    pub fn captured(self, case: &str) -> Self {
        self.truncating(case, case)
    }

    /// Answers the question of the captured responses `udp` and `tcp`, which share it, with the first over UDP
    /// and the second over TCP: a truncated response then the whole one (RFC 1035 §4.2.1).
    ///
    /// # Panics
    ///
    /// When a file is missing, is not a response with a question, or the questions differ.
    #[must_use]
    pub fn truncating(mut self, udp: &str, tcp: &str) -> Self {
        let (udp, tcp) = (captured(udp), captured(tcp));
        let question = question(&udp);
        assert_eq!(question, self::question(&tcp), "one question");
        self.entries.push(Entry { question, udp, tcp });
        self
    }

    /// Puts an attacker on the host of the server: it sends what `attacker` says for each query over UDP.
    #[must_use]
    pub fn attacked_by(mut self, attacker: Attacker) -> Self {
        self.attacker = Some(attacker);
        self
    }

    /// What the server answers, to compare with what clients get: the whole response of each entry.
    pub(crate) fn expected(&self) -> impl Iterator<Item = Expected> {
        self.entries.iter().map(|entry| {
            let message = Message::decode(&entry.tcp)
                .expect("a captured response decodes")
                .message
                .into_owned();
            Expected {
                question: entry.question.clone(),
                rcode: message.rcode(),
                answer: message.answer,
            }
        })
    }

    /// The response to the query `wire`, with its ID, and the question it answers; none for what a server does
    /// not answer: a message that is no query, or a question it holds nothing for.
    fn reply(&self, wire: &[u8], transport: Transport) -> Option<(Vec<u8>, Question<'static>)> {
        let decoded = Message::decode(wire).ok()?;
        if decoded.message.header.flags.contains(Flags::QR) {
            return None;
        }
        let asked = decoded.message.questions.first()?;
        let entry = self.entries.iter().find(|entry| entry.question == *asked)?;
        let mut reply = if transport == Transport::Tcp {
            entry.tcp.clone()
        } else {
            entry.udp.clone()
        };
        reply.get_mut(..2)?.copy_from_slice(wire.get(..2)?);
        Some((reply, entry.question.clone()))
    }
}

/// The software of an upstream server host: answers on port 53 until the host crashes.
///
/// # Errors
///
/// A socket that fails, or a task that panics.
pub async fn serve(answers: Rc<Answers>, host: IpAddr, trace: Trace) -> turmoil::Result {
    let mut port = Port::bind().await?;
    loop {
        match port.next().await? {
            Arrival::Datagram { wire, from } => {
                let reply = answers.reply(&wire, Transport::Udp);
                if let Some(attacker) = &answers.attacker {
                    let genuine = reply.as_ref().map(|(reply, _)| reply.as_slice());
                    let seen = Seen {
                        query: &wire,
                        from,
                        genuine,
                    };
                    for injection in attacker.react(&seen) {
                        port.spawn(inject(port.udp(), from, injection, host, trace.clone()));
                    }
                }
                if let Some((reply, question)) = reply {
                    trace.record(
                        host,
                        What::Served {
                            question,
                            transport: Transport::Udp,
                        },
                    );
                    port.udp().send_to(&reply, from).await.ok();
                }
            }
            Arrival::Connection { stream, .. } => {
                port.spawn(connection(Rc::clone(&answers), stream, host, trace.clone()));
            }
        }
    }
}

/// Sends `injection` to `to` from the server's socket, after its delay.
async fn inject(
    socket: Rc<UdpSocket>,
    to: SocketAddr,
    injection: Injection,
    host: IpAddr,
    trace: Trace,
) {
    tokio::time::sleep(injection.after).await;
    trace.record(
        host,
        What::Injected {
            to,
            after: injection.after,
        },
    );
    socket.send_to(&injection.wire, to).await.ok();
}

/// Answers the queries of a connection, one at a time, until it closes.
async fn connection(answers: Rc<Answers>, mut stream: TcpStream, host: IpAddr, trace: Trace) {
    while let Ok(query) = framing::read(&mut stream).await {
        let Some((reply, question)) = answers.reply(&query, Transport::Tcp) else {
            continue;
        };
        trace.record(
            host,
            What::Served {
                question,
                transport: Transport::Tcp,
            },
        );
        if framing::write(&mut stream, &reply).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use dedens_proto::Ttl;

    use super::*;

    fn held(case: &str) -> Expected {
        Answers::new()
            .captured(case)
            .expected()
            .next()
            .expect("one entry")
    }

    fn message(case: &str) -> Message<'static> {
        Message::decode(&captured(case))
            .expect("a captured response decodes")
            .message
            .into_owned()
    }

    #[test]
    fn the_data_matches_itself_whatever_the_ttls() {
        // One record or several, an answer or none.
        for case in ["a", "soa", "nodata", "nxdomain_soa"] {
            let mut got = message(case);
            for record in &mut got.answer {
                record.ttl = Ttl::ZERO;
            }
            assert!(held(case).matches(&got.questions[0], &got), "{case}");
        }
    }

    #[test]
    fn other_data_does_not_match() {
        let held = held("a");
        let mut fewer = message("a");
        fewer.answer.pop();
        assert!(!held.matches(&fewer.questions[0], &fewer));
        let mut more = message("a");
        more.answer.extend(message("txt_large").answer);
        assert!(!held.matches(&more.questions[0], &more));
        let mut other = message("a");
        other.answer = message("txt_large").answer;
        assert!(!held.matches(&other.questions[0], &other));
        let mut refused = message("a");
        refused.set_rcode(Rcode::REFUSED).expect("a response code");
        assert!(!held.matches(&refused.questions[0], &refused));
        // Same names and classes, a record of another data: the two A records are not the same twice over.
        let mut twice = message("a");
        twice.answer[0].rdata = twice.answer[1].rdata.clone();
        assert!(!held.matches(&twice.questions[0], &twice));
        // The data of the records, under another name.
        let mut renamed = message("a");
        let name = message("txt_large").answer[0].name.clone();
        for record in &mut renamed.answer {
            record.name = name.clone();
        }
        assert!(!held.matches(&renamed.questions[0], &renamed));
        let elsewhere = message("txt_large");
        assert!(!held.matches(&elsewhere.questions[0], &elsewhere));
        // The question asked is the one held, whatever the message says.
        let got = message("a");
        assert!(!held.matches(&elsewhere.questions[0], &got));
    }
}
