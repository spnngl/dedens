//! An upstream server: answers from responses captured from real servers, with the query's ID, over UDP and TCP.
//!
//! What it answers: the capture for a question it holds, cut to the UDP payload size the query announces (512
//! bytes without EDNS, RFC 6891 §6.2.3) with TC set when it is longer; REFUSED for another question; nothing to a
//! message that is no query. It sends an EDNS cookie when told to ([`Answers::cookies`]).
//!
//! Left out: the zone data of a real server; a scenario that needs it adds a pipeline with a local-data stage here.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::rc::Rc;

use dedens_proto::edns::{Cookie, Edns, EdnsOption};
use dedens_proto::{Flags, Message, Question, Rcode, Transport};
use turmoil::net::{TcpStream, UdpSocket};

use crate::attacker::{Attacker, Injection, Seen};
use crate::framing;
use crate::oracle::Expected;
use crate::port::{Arrival, Port};
use crate::trace::{Trace, What};

/// The size of the buffer a reply is made in: the largest message.
const OUT: usize = 65535;

/// What a message that is not cut is allowed over UDP without EDNS (RFC 1035 §4.2.1).
const PLAIN_PAYLOAD: usize = 512;

/// The responses an upstream server holds, each for a question, and the attacker on its host, if any.
#[derive(Debug, Default, Clone)]
pub struct Answers {
    entries: Vec<Entry>,
    attacker: Option<Attacker>,
    cookie: Option<[u8; 8]>,
}

#[derive(Debug, Clone)]
struct Entry {
    question: Question<'static>,
    udp: Vec<u8>,
    tcp: Vec<u8>,
}

/// A response captured from a real server, in `crates/dedens-proto/tests/testdata`.
pub(crate) fn captured(case: &str) -> Vec<u8> {
    let path = format!(
        "{}/../dedens-proto/tests/testdata/{case}.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("a captured response")
}

/// The captured response `case`, decoded.
#[cfg(test)]
pub(crate) fn captured_message(case: &str) -> Message<'static> {
    decode(&captured(case))
}

/// The message of a response: a capture decodes.
fn decode(wire: &[u8]) -> Message<'static> {
    Message::decode(wire)
        .expect("a captured response decodes")
        .message
        .into_owned()
}

/// The question of a response.
fn question(wire: &[u8]) -> Question<'static> {
    decode(wire).questions.swap_remove(0)
}

impl Answers {
    /// No responses: the server answers REFUSED.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers the question of the captured response `case` of `dedens-proto`'s test data with it, over UDP and
    /// TCP.
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

    /// Answers the question of the response in the file `path`, over UDP and TCP.
    ///
    /// # Panics
    ///
    /// When the file is missing or is not a response with a question.
    #[must_use]
    pub fn file(mut self, path: &Path) -> Self {
        let wire = std::fs::read(path).expect("a captured response");
        let question = question(&wire);
        self.entries.push(Entry {
            question,
            udp: wire.clone(),
            tcp: wire,
        });
        self
    }

    /// Answers the question of each `.bin` response of the directory `dir`, such as
    /// `crates/dedens-dnssec/tests/testdata`, taken in the order of their names; of two for one question, the
    /// first is the one.
    ///
    /// # Panics
    ///
    /// When the directory is missing, or a `.bin` file is not a response with a question.
    #[must_use]
    pub fn directory(mut self, dir: &Path) -> Self {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .expect("a directory of captured responses")
            .map(|file| file.expect("a readable directory").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "bin"))
            .collect();
        files.sort();
        for path in files {
            let held = Self::new().file(&path);
            for entry in held.entries {
                if !self
                    .entries
                    .iter()
                    .any(|known| known.question == entry.question)
                {
                    self.entries.push(entry);
                }
            }
        }
        self
    }

    /// Puts an attacker on the host of the server: it sends what `attacker` says for each query over UDP.
    #[must_use]
    pub fn attacked_by(mut self, attacker: Attacker) -> Self {
        self.attacker = Some(attacker);
        self
    }

    /// Has the server answer a query with a client cookie with it and `server` as the server cookie (RFC 7873
    /// §5.2).
    #[must_use]
    pub const fn cookies(mut self, server: [u8; 8]) -> Self {
        self.cookie = Some(server);
        self
    }

    /// What the server answers, to compare with what clients get: the whole response of each entry.
    pub(crate) fn expected(&self) -> impl Iterator<Item = Expected> {
        self.entries
            .iter()
            .map(|entry| Expected::of(&decode(&entry.tcp)))
    }

    /// The response to the query `wire`, with its ID, and the question it answers; none for what a server does
    /// not answer: a message that is no query.
    fn reply(&self, wire: &[u8], transport: Transport) -> Option<(Vec<u8>, Question<'static>)> {
        let query = Message::decode(wire).ok()?.message.into_owned();
        if query.header.flags.contains(Flags::QR) {
            return None;
        }
        let asked = query.questions.first()?.clone();
        let mut reply = match self.entries.iter().find(|entry| entry.question == asked) {
            Some(entry) => self.answer(entry, &query, transport)?,
            None => refusal(&query)?,
        };
        reply.get_mut(..2)?.copy_from_slice(wire.get(..2)?);
        Some((reply, asked))
    }

    /// The capture for `query`: cut to its payload size over UDP, with the cookie if it sent one.
    fn answer(
        &self,
        entry: &Entry,
        query: &Message<'static>,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let tcp = transport == Transport::Tcp;
        let capture = if tcp { &entry.tcp } else { &entry.udp };
        let limit = query.edns.as_ref().map_or(PLAIN_PAYLOAD, |edns| {
            usize::from(edns.udp_payload).max(PLAIN_PAYLOAD)
        });
        let cookie = self.cookie.zip(client_cookie(query));
        if cookie.is_none() && (tcp || capture.len() <= limit) {
            return Some(capture.clone());
        }
        let mut message = decode(capture);
        if let Some((server, client)) = cookie {
            let cookie = Cookie::new(client, Some(&server)).ok()?;
            message
                .edns
                .get_or_insert_with(Edns::default)
                .options
                .push(EdnsOption::Cookie(cookie));
        }
        let mut out = vec![0; OUT];
        let len = if tcp {
            message.encode(&mut out).ok()?
        } else {
            let cut = out.get_mut(..limit.min(OUT))?;
            message.encode_truncated(cut).ok()?.len
        };
        out.truncate(len);
        Some(out)
    }
}

/// The client cookie of `query`.
fn client_cookie(query: &Message<'_>) -> Option<[u8; 8]> {
    query
        .edns
        .iter()
        .flat_map(|edns| &edns.options)
        .find_map(|option| match option {
            EdnsOption::Cookie(cookie) => Some(cookie.client()),
            _ => None,
        })
}

/// REFUSED, with the question: what a server answers to a zone it is not for (RFC 1035 §4.1.1).
fn refusal(query: &Message<'static>) -> Option<Vec<u8>> {
    let mut reply = query.clone();
    reply.header.flags = reply.header.flags.with(Flags::QR);
    reply.set_rcode(Rcode::REFUSED).ok()?;
    if let Some(edns) = reply.edns.as_mut() {
        edns.options.clear();
    }
    let mut out = vec![0; OUT];
    let len = reply.encode(&mut out).ok()?;
    out.truncate(len);
    Some(out)
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
                            len: reply.len(),
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
                len: reply.len(),
            },
        );
        if framing::write(&mut stream, &reply).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use dedens_proto::RecordType;

    use super::*;
    use crate::stub::question as ask;

    /// The wire of a query for `question` with ID 0x1234, announcing `payload` bytes if EDNS is on.
    fn query(
        question: Question<'static>,
        payload: Option<u16>,
        client: Option<[u8; 8]>,
    ) -> Vec<u8> {
        let mut message = Message::query(0x1234, question);
        match payload {
            Some(payload) => {
                let edns = message.edns.as_mut().expect("EDNS");
                edns.udp_payload = payload;
                if let Some(client) = client {
                    let cookie = Cookie::new(client, None).expect("a client cookie");
                    edns.options.push(EdnsOption::Cookie(cookie));
                }
            }
            None => message.edns = None,
        }
        let mut out = vec![0; OUT];
        let len = message.encode(&mut out).expect("encodes");
        out.truncate(len);
        out
    }

    fn txt() -> Question<'static> {
        question(&captured("txt_large"))
    }

    #[test]
    fn a_question_it_holds_nothing_for_is_refused() {
        let answers = Answers::new().captured("a");
        let wire = query(ask("nothing.example", RecordType::A), Some(1232), None);
        let (reply, _) = answers.reply(&wire, Transport::Udp).expect("a reply");
        let reply = decode(&reply);
        assert_eq!(reply.header.id, 0x1234);
        assert!(reply.header.flags.contains(Flags::QR));
        assert_eq!(reply.rcode(), Rcode::REFUSED);
        assert_eq!(reply.questions, [ask("nothing.example", RecordType::A)]);
        assert_eq!(reply.answer, Vec::new());
    }

    #[test]
    fn a_message_that_is_no_query_gets_nothing() {
        let answers = Answers::new().captured("a");
        assert!(answers.reply(&captured("a"), Transport::Udp).is_none());
        assert!(answers.reply(&[1, 2, 3], Transport::Udp).is_none());
    }

    #[test]
    fn a_reply_is_cut_to_the_payload_the_query_announces() {
        let answers = Answers::new().captured("txt_large");
        let whole = captured("txt_large");
        for payload in [None, Some(512), Some(700)] {
            let (reply, _) = answers
                .reply(&query(txt(), payload, None), Transport::Udp)
                .expect("a reply");
            let limit = payload.map_or(512, usize::from);
            assert!(reply.len() <= limit, "{payload:?}: {}", reply.len());
            let reply = decode(&reply);
            assert!(reply.header.flags.contains(Flags::TC), "{payload:?}");
            assert!(
                reply.answer.len() < decode(&whole).answer.len(),
                "{payload:?}"
            );
        }
        // Room enough, or TCP: the capture, with the ID of the query.
        for (payload, transport) in [(4096, Transport::Udp), (512, Transport::Tcp)] {
            let (reply, _) = answers
                .reply(&query(txt(), Some(payload), None), transport)
                .expect("a reply");
            assert_eq!(reply.get(2..), whole.get(2..), "{payload} {transport:?}");
            assert_eq!(reply.get(..2), Some([0x12, 0x34].as_slice()));
        }
    }

    #[test]
    fn a_client_cookie_gets_the_server_cookie_with_it() {
        let client = [7; 8];
        let wire = query(ask("example.com", RecordType::A), Some(1232), Some(client));
        let plain = Answers::new().captured("a");
        let (reply, _) = plain.reply(&wire, Transport::Udp).expect("a reply");
        assert_eq!(client_cookie(&decode(&reply)), None);
        let cookies = plain.cookies([9; 8]);
        let (reply, _) = cookies.reply(&wire, Transport::Udp).expect("a reply");
        let reply = decode(&reply);
        let sent = client_cookie(&reply).expect("a cookie");
        assert_eq!(sent, client);
        // Without a client cookie, there is none to answer.
        let wire = query(ask("example.com", RecordType::A), Some(1232), None);
        let (reply, _) = cookies.reply(&wire, Transport::Udp).expect("a reply");
        assert_eq!(client_cookie(&decode(&reply)), None);
    }

    #[test]
    fn a_directory_holds_the_first_response_of_each_question() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../dedens-dnssec/tests/testdata");
        let answers = Answers::new().directory(&dir);
        let count = answers.expected().count();
        assert!(count > 100, "{count}");
        let all = answers.entries.len();
        assert_eq!(answers.directory(&dir).entries.len(), all, "twice the same");
    }
}
