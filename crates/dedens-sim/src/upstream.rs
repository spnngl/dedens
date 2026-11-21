//! An upstream server: answers from responses captured from real servers, with the query's ID, over UDP and TCP
//! (and TLS, through [`crate::dot`]).
//!
//! What it answers: the capture for a question it holds, cut to the UDP payload size the query announces (512
//! bytes without EDNS, RFC 6891 §6.2.3) with TC set when it is longer; REFUSED for another question; nothing to a
//! message that is no query. A query without DO gets the capture without its RRSIG, NSEC and NSEC3 records, as a
//! server sends it (RFC 4035 §3.2.1). It sends an EDNS cookie when told to ([`Answers::cookies`]).
//!
//! What goes wrong is the scenario's: [`Answers::faulty`] decides, for each response and from the host's seeded
//! stream, whether it is sent, dropped or delayed ([`Verdict`]); [`Answers::silent`] sends none;
//! [`Answers::tcp`] makes the server answer, ignore or close a connection ([`Behaviour`]), TCP or TLS; [`Answers::attacked_by`] puts an
//! attacker on its socket; [`Answers::conduct`] changes every response as a broken server does ([`Conduct`]).
//!
//! The same server stands at each address of a captured resolution, an authoritative server of the Internet,
//! answering the exchanges captured from it ([`Answers::exchanges`], D189).
//!
//! Left out: the zone data of a real server; a scenario that needs it adds a pipeline with a local-data stage here.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use compio::io::BufReader;
use compio::io::util::Splittable as _;
use dedens_net::tcp::{Inbound, Outbound};
use dedens_proto::edns::{Cookie, Edns, EdnsFlags, EdnsOption};
use dedens_proto::{Flags, HEADER_LEN, MAX_NAME_LEN, Message, Question, Rcode, Transport};
pub(crate) use dedens_testkit::captured;
use dedens_testkit::recursion::{self, Exchange};
use tokio::task::JoinSet;
use turmoil::net::{TcpStream, UdpSocket};

use crate::attacker::{Attacker, Injection, Seen};
use crate::io::SimStream;
use crate::oracle::{Expected, withheld};
use crate::port::{Arrival, Port};
use crate::seed::Rng;
use crate::trace::{Trace, What};

/// The size of the buffer a reply is made in: the largest message.
const OUT: usize = 65535;

/// What a message that is not cut is allowed over UDP without EDNS (RFC 1035 §4.2.1).
const PLAIN_PAYLOAD: usize = 512;

/// What a server does with a response it is about to send: the verdict of [`Answers::faulty`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Sends it.
    Answer,
    /// Never sends it: a lost response, or a server that does not answer.
    Drop,
    /// Sends it after this long, while it goes on answering: a slow server, a response that comes late.
    Delay(Duration),
}

/// What a server does over TCP and TLS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Behaviour {
    /// Answers each query.
    #[default]
    Answer,
    /// Reads the queries of a connection and never answers.
    Silent,
    /// Answers this many queries of a connection, then closes it: none, and it closes as it is made.
    Close(usize),
}

/// How a server answers, each way but [`Conduct::Faithful`] a broken server of the Internet, the capture changed as it
/// changes it (D189). A server that never answers, lame by timeout, is [`Answers::silent`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Conduct {
    /// Answers with the capture.
    #[default]
    Faithful,
    /// Answers REFUSED to every query, the question and nothing else: a lame server, not configured for the zone
    /// delegated to it (RFC 4697 §2.1.1).
    Refuses,
    /// Answers SERVFAIL to every query, as REFUSED: a server failing to load its zone (RFC 4697 §2.1.1).
    Fails,
    /// Sets TC in every response over UDP and sends the header, the question and the OPT record alone, as a
    /// server whose response rate limiting slips every answer does: the whole capture comes over TCP alone (RFC
    /// 7766 §5).
    Truncates,
    /// Implements no EDNS: answers FORMERR without an OPT record to a query with one, and the capture without its
    /// OPT record, cut to 512 bytes over UDP, to a query without (RFC 6891 §7).
    NoEdns,
    /// Writes the question in lowercase, not in the case asked: the server `0x20` loses (D184).
    FoldsCase,
    /// Answers with the capture, AA clear: a server answering for a zone it is not authoritative for, from a cache
    /// or another server's copy, which a resolver takes for lame (RFC 4697 §2.1.1). A referral, never
    /// authoritative, is what it was.
    Unauthoritative,
}

/// What decides the [`Verdict`] for a question, from the host's own stream of the seed.
type Decide = dyn Fn(&Question<'static>, &mut Rng) -> Verdict;

#[derive(Clone)]
struct Fickle(Rc<Decide>);

impl fmt::Debug for Fickle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fickle(..)")
    }
}

/// What makes the response to a question, if the scenario has one: [`Answers::derived`].
type Derive = dyn Fn(&Question<'static>) -> Option<Vec<u8>>;

#[derive(Clone)]
struct Derived(Rc<Derive>);

impl fmt::Debug for Derived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Derived(..)")
    }
}

/// One UDP response in `one_in` lost: [`Answers::lossy`].
#[derive(Debug, Clone)]
struct Loss {
    one_in: NonZeroU64,
    /// How many responses go out before the next lost, drawn at the first; shared by the clones of the answers.
    next: Rc<Cell<Option<u64>>>,
}

/// The responses an upstream server holds, each for a question, and the attacker on its host, if any.
#[derive(Debug, Default, Clone)]
pub struct Answers {
    entries: Vec<Entry>,
    attacker: Option<Attacker>,
    cookie: Option<[u8; 8]>,
    fickle: Option<Fickle>,
    /// The responses made for the question, ahead of the entries: [`Answers::derived`].
    derived: Option<Derived>,
    /// The UDP responses lost, if any: [`Answers::lossy`].
    loss: Option<Loss>,
    tcp: Behaviour,
    conduct: Conduct,
    /// The connections the host accepted, over every start of it and in every clone of these answers.
    connections: Rc<Cell<usize>>,
    /// The connections that ended, as [`Answers::connections`].
    ended: Rc<Cell<usize>>,
}

/// A capture, as sent to a query with DO and as sent to one without (RFC 4035 §3.2.1): a server sends the
/// signatures and the proofs of non-existence only to a client that asks for them.
#[derive(Debug, Clone)]
struct Entry {
    question: Question<'static>,
    udp: Vec<u8>,
    tcp: Vec<u8>,
    plain_udp: Vec<u8>,
    plain_tcp: Vec<u8>,
}

impl Entry {
    fn new(question: Question<'static>, udp: Vec<u8>, tcp: Vec<u8>) -> Self {
        Self {
            plain_udp: plain(&udp, &question),
            plain_tcp: plain(&tcp, &question),
            question,
            udp,
            tcp,
        }
    }
}

/// `wire` without the RRSIG, NSEC and NSEC3 records `question` did not ask for: as it is when it has none.
fn plain(wire: &[u8], question: &Question<'static>) -> Vec<u8> {
    let mut message = decode(wire);
    let size = |message: &Message<'_>| {
        message.answer.len() + message.authority.len() + message.additional.len()
    };
    let held = size(&message);
    for section in [
        &mut message.answer,
        &mut message.authority,
        &mut message.additional,
    ] {
        section.retain(|record| !withheld(record, question));
    }
    if size(&message) == held {
        return wire.to_vec();
    }
    let mut out = vec![0; OUT];
    let len = message
        .encode(&mut out)
        .expect("a message it decoded encodes");
    out.truncate(len);
    out
}

/// The captured response `case`, decoded.
#[cfg(test)]
pub(crate) fn captured_message(case: &str) -> Message<'static> {
    decode(&captured(case))
}

/// The message of a response: a capture decodes.
pub(crate) fn decode(wire: &[u8]) -> Message<'static> {
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
        self.entries.push(Entry::new(question, udp, tcp));
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
        self.entries.push(Entry::new(question, wire.clone(), wire));
        self
    }

    /// Answers the question of each `.bin` response of the directory `dir`, such as
    /// `testdata/dnssec`, taken in the order of their names; of two for one question, the
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

    /// Answers the question of each of `exchanges`, those of one server in a captured resolution (D188), with its
    /// response: over UDP the one captured over UDP, over TCP the one captured over TCP, the UDP one when none was
    /// (the transport's own response, as [`Answers::truncating`]). A question already held keeps its response.
    ///
    /// # Panics
    ///
    /// When a response does not decode.
    #[must_use]
    pub fn exchanges<'e>(mut self, exchanges: impl IntoIterator<Item = &'e Exchange>) -> Self {
        let exchanges: Vec<&Exchange> = exchanges.into_iter().collect();
        for exchange in &exchanges {
            let question = Question::new(exchange.name.clone(), exchange.rtype);
            if self.entries.iter().any(|known| known.question == question) {
                continue;
            }
            let over = |transport| {
                exchanges
                    .iter()
                    .find(|other| {
                        other.transport == transport
                            && other.name == exchange.name
                            && other.rtype == exchange.rtype
                    })
                    .map(|other| other.response.clone())
            };
            let udp = over(recursion::Transport::Udp).unwrap_or_else(|| exchange.response.clone());
            let tcp = over(recursion::Transport::Tcp).unwrap_or_else(|| udp.clone());
            self.entries.push(Entry::new(question, udp, tcp));
        }
        self
    }

    /// Has the server answer a question with the response `derive` makes for it, ahead of the captures it holds:
    /// a capture changed as an attack changes it, for the names a scenario cannot list (a thousand of them, a
    /// random one for each query), or for a time (read `turmoil::sim_elapsed`): a delegation that is revoked. `None`
    /// leaves the question to the captures. The response goes the way a capture does: the ID and the case of the
    /// query, cut to its payload size over UDP with TC, DNSSEC records only for DO.
    #[must_use]
    pub fn derived(
        mut self,
        derive: impl Fn(&Question<'static>) -> Option<Vec<u8>> + 'static,
    ) -> Self {
        self.derived = Some(Derived(Rc::new(derive)));
        self
    }

    /// Has the server answer as `conduct` says.
    #[must_use]
    pub const fn conduct(mut self, conduct: Conduct) -> Self {
        self.conduct = conduct;
        self
    }

    /// Puts an attacker on the host of the server: it sends what `attacker` says for each query over UDP.
    #[must_use]
    pub fn attacked_by(mut self, attacker: Attacker) -> Self {
        self.attacker = Some(attacker);
        self
    }

    /// Has `decide` rule on each response before it goes out, from the stream of the seed of this host: a server
    /// that loses, delays or never sends what a scenario tells it to, at random when `decide` draws. The
    /// attacker's datagrams are not its responses.
    #[must_use]
    pub fn faulty(
        mut self,
        decide: impl Fn(&Question<'static>, &mut Rng) -> Verdict + 'static,
    ) -> Self {
        self.fickle = Some(Fickle(Rc::new(decide)));
        self
    }

    /// Has the server lose one UDP response in `one_in` of those [`Answers::faulty`] lets out: one at random among
    /// the first `one_in`, from the stream of the seed of this host, then every `one_in`th, a datagram lost on its way.
    /// Never two in a row: three in a row would have the resolver skip a zone's only server (D194). Over TCP a lost
    /// segment is sent again, the response late, never lost (D196).
    #[must_use]
    pub fn lossy(mut self, one_in: NonZeroU64) -> Self {
        self.loss = Some(Loss {
            one_in,
            next: Rc::default(),
        });
        self
    }

    /// A server that never answers: [`Verdict::Drop`] for each response, over UDP, TCP and TLS.
    #[must_use]
    pub fn silent(self) -> Self {
        self.faulty(|_, _| Verdict::Drop)
    }

    /// The number of TCP and TLS connections the server accepted so far, to read after the run: how a pool reuses its
    /// connections (D27). Clones of these answers share it.
    #[must_use]
    pub fn connections(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.connections)
    }

    /// Notes an accepted connection.
    pub(crate) fn accepted(&self) {
        self.connections.set(self.connections.get() + 1);
    }

    /// Notes a connection that ended.
    pub(crate) fn closed(&self) {
        self.ended.set(self.ended.get() + 1);
    }

    /// The number of TCP and TLS connections that ended so far, closed by the client or by the server, as
    /// [`Answers::connections`]: when a pool lets its connections go.
    #[must_use]
    pub fn ended(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.ended)
    }

    /// Has the server behave as `behaviour` over TCP and TLS: it accepts connections whatever it does with them.
    #[must_use]
    pub const fn tcp(mut self, behaviour: Behaviour) -> Self {
        self.tcp = behaviour;
        self
    }

    /// Has the server answer a query with a client cookie with it and `server` as the server cookie (RFC 7873
    /// §5.2).
    #[must_use]
    pub const fn cookies(mut self, server: [u8; 8]) -> Self {
        self.cookie = Some(server);
        self
    }

    /// The verdict on the response to `question`: [`Verdict::Answer`] unless [`Answers::faulty`] says otherwise.
    fn verdict(&self, question: &Question<'static>, rng: &RefCell<Rng>) -> Verdict {
        self.fickle.as_ref().map_or(Verdict::Answer, |fickle| {
            (fickle.0)(question, &mut rng.borrow_mut())
        })
    }

    /// The verdict on the UDP response to `question`, [`Answers::verdict`]'s unless [`Answers::lossy`] loses it.
    fn udp_verdict(&self, question: &Question<'static>, rng: &RefCell<Rng>) -> Verdict {
        let verdict = self.verdict(question, rng);
        let lost = |loss: &Loss| {
            let next =
                (loss.next.get()).unwrap_or_else(|| rng.borrow_mut().below(loss.one_in.get()));
            loss.next
                .set(Some(next.checked_sub(1).unwrap_or(loss.one_in.get() - 1)));
            next == 0
        };
        if verdict != Verdict::Drop && self.loss.as_ref().is_some_and(lost) {
            Verdict::Drop
        } else {
            verdict
        }
    }

    /// What the server answers, to compare with what clients get: the whole response of each entry.
    pub(crate) fn expected(&self) -> impl Iterator<Item = Expected> {
        self.entries
            .iter()
            .map(|entry| Expected::of(&decode(&entry.tcp)))
    }

    /// The response to the query `wire`, with its ID, and the question it answers; none for what a server does
    /// not answer: a message that is no query.
    pub(crate) fn reply(
        &self,
        wire: &[u8],
        transport: Transport,
    ) -> Option<(Vec<u8>, Question<'static>)> {
        let query = Message::decode(wire).ok()?.message.into_owned();
        if query.header.flags.contains(Flags::QR) {
            return None;
        }
        let asked = query.questions.first()?.clone();
        let made = (self.derived.as_ref())
            .and_then(|derived| (derived.0)(&asked))
            .map(|wire| Entry::new(asked.clone(), wire.clone(), wire));
        let held = made
            .as_ref()
            .or_else(|| self.entries.iter().find(|entry| entry.question == asked));
        let mut reply = match (self.conduct, held) {
            (Conduct::Refuses, _) | (_, None) => refusal(&query, Rcode::REFUSED)?,
            (Conduct::Fails, _) => refusal(&query, Rcode::SERVFAIL)?,
            (Conduct::NoEdns, _) if query.edns.is_some() => {
                let plain = Message {
                    edns: None,
                    ..query.clone()
                };
                refusal(&plain, Rcode::FORMERR)?
            }
            (_, Some(entry)) => self.answer(entry, &query, transport)?,
        };
        reply.get_mut(..2)?.copy_from_slice(wire.get(..2)?);
        // The question as asked, in its case: a server copies it (RFC 1035 §4.1.1), which `0x20` relies on (D184).
        let mut buf = [0; MAX_NAME_LEN];
        let name = asked.name.to_wire(&mut buf);
        if let Some(echo) = reply.get_mut(HEADER_LEN..HEADER_LEN + name.len())
            && echo.eq_ignore_ascii_case(name)
        {
            if self.conduct == Conduct::FoldsCase {
                // The lengths of the labels are at most 63, below `A`: only the letters change.
                echo.make_ascii_lowercase();
            } else {
                echo.copy_from_slice(name);
            }
        }
        Some((reply, asked))
    }

    /// The capture for `query`: cut to its payload size over UDP, with the cookie if it sent one, changed as
    /// [`Answers::conduct`] says.
    fn answer(
        &self,
        entry: &Entry,
        query: &Message<'static>,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        // Only UDP cuts a message; every other transport carries it whole.
        let tcp = transport != Transport::Udp;
        let dnssec = query
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags.contains(EdnsFlags::DO));
        let capture = match (tcp, dnssec) {
            (true, true) => &entry.tcp,
            (true, false) => &entry.plain_tcp,
            (false, true) => &entry.udp,
            (false, false) => &entry.plain_udp,
        };
        let limit = query.edns.as_ref().map_or(PLAIN_PAYLOAD, |edns| {
            usize::from(edns.udp_payload).max(PLAIN_PAYLOAD)
        });
        let cookie = self.cookie.zip(client_cookie(query));
        let changed = matches!(
            self.conduct,
            Conduct::Truncates | Conduct::NoEdns | Conduct::Unauthoritative
        );
        if cookie.is_none() && !changed && (tcp || capture.len() <= limit) {
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
        match self.conduct {
            Conduct::Truncates if !tcp => {
                message.header.flags = message.header.flags.with(Flags::TC);
                message.answer.clear();
                message.authority.clear();
                message.additional.clear();
            }
            // The query has no OPT record: one with gets FORMERR (`reply`).
            Conduct::NoEdns => message.edns = None,
            Conduct::Unauthoritative => {
                message.header.flags = message.header.flags.without(Flags::AA);
            }
            _ => {}
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

/// `rcode` with the question and nothing else: REFUSED is what a server answers to a zone it is not for (RFC 1035
/// §4.1.1).
fn refusal(query: &Message<'static>, rcode: Rcode) -> Option<Vec<u8>> {
    let mut reply = query.clone();
    reply.header.flags = reply.header.flags.with(Flags::QR);
    reply.set_rcode(rcode).ok()?;
    if let Some(edns) = reply.edns.as_mut() {
        edns.options.clear();
    }
    let mut out = vec![0; OUT];
    let len = reply.encode(&mut out).ok()?;
    out.truncate(len);
    Some(out)
}

/// The software of an upstream server host: answers on port 53 until the host crashes. `rng` is the host's stream of
/// the seed, for [`Answers::faulty`]; it goes on where it left off when the host restarts.
///
/// # Errors
///
/// A socket that fails, or a task that panics.
pub async fn serve(
    answers: Rc<Answers>,
    host: IpAddr,
    rng: Rc<RefCell<Rng>>,
    trace: Trace,
) -> turmoil::Result {
    let mut port = Port::bind(host).await?;
    loop {
        match port.next().await? {
            Arrival::Datagram { wire, from } => {
                let reply = answers.reply(&wire, Transport::Udp);
                let mut genuine = true;
                if let Some(attacker) = &answers.attacker {
                    let seen = Seen {
                        query: &wire,
                        from,
                        genuine: reply.as_ref().map(|(reply, _)| reply.as_slice()),
                    };
                    let reaction = attacker.react(&seen);
                    genuine = reaction.genuine;
                    for injection in reaction.injections {
                        port.spawn(inject(port.udp(), from, injection, host, trace.clone()));
                    }
                }
                let Some((reply, question)) = reply.filter(|_| genuine) else {
                    continue;
                };
                let sent = Sent {
                    question,
                    transport: Transport::Udp,
                };
                match answers.udp_verdict(&sent.question, &rng) {
                    Verdict::Drop => {}
                    Verdict::Answer => send(&port.udp(), from, &reply, sent, host, &trace).await,
                    Verdict::Delay(delay) => {
                        let (socket, trace) = (port.udp(), trace.clone());
                        port.spawn(async move {
                            tokio::time::sleep(delay).await;
                            send(&socket, from, &reply, sent, host, &trace).await;
                        });
                    }
                }
            }
            Arrival::Connection { stream, .. } => {
                answers.accepted();
                let (answers, rng) = (Rc::clone(&answers), Rc::clone(&rng));
                port.spawn(connection(answers, stream, host, rng, trace.clone()));
            }
        }
    }
}

/// A response on its way out: what the trace records of it.
struct Sent {
    question: Question<'static>,
    transport: Transport,
}

/// Sends `reply` to `to` from `socket`, and records it.
async fn send(
    socket: &UdpSocket,
    to: SocketAddr,
    reply: &[u8],
    sent: Sent,
    host: IpAddr,
    trace: &Trace,
) {
    trace.record(
        host,
        What::Served {
            question: sent.question,
            transport: sent.transport,
        },
    );
    socket.send_to(reply, to).await.ok();
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

/// Serves the queries of a TCP connection (see [`queries`]), then counts it ended.
async fn connection(
    answers: Rc<Answers>,
    stream: TcpStream,
    host: IpAddr,
    rng: Rc<RefCell<Rng>>,
    trace: Trace,
) {
    // A stream closed as it was accepted has nothing to serve.
    if let Ok(stream) = SimStream::new(stream) {
        let (reader, writer) = stream.split();
        let reader = BufReader::new(reader);
        queries(&answers, Transport::Tcp, reader, writer, host, &rng, &trace).await;
    }
    answers.closed();
}

/// Serves the queries of a connection over `transport`, TCP or TLS, as [`Answers::tcp`] and [`Answers::faulty`] say,
/// until it closes: each query is read as it comes, and a delayed response does not hold the ones behind it (RFC
/// 7766 §6.2.1.1, RFC 7858 §3.3, as a pipelining server does), so a pooled connection does not stall on one slow
/// answer. The delayed responses go out before this side closes, over TLS after a `close_notify`.
pub(crate) async fn queries<W: Outbound + 'static>(
    answers: &Answers,
    transport: Transport,
    mut reader: impl Inbound,
    writer: W,
    host: IpAddr,
    rng: &RefCell<Rng>,
    trace: &Trace,
) {
    let writer = Rc::new(tokio::sync::Mutex::new(writer));
    let mut delayed = JoinSet::new();
    let mut served = 0;
    loop {
        if matches!(answers.tcp, Behaviour::Close(limit) if served >= limit) {
            break;
        }
        let Ok(query) = reader.message().await else {
            break;
        };
        trace.record(host, What::Received { transport });
        if answers.tcp == Behaviour::Silent {
            continue;
        }
        let Some((reply, question)) = answers.reply(&query, transport) else {
            continue;
        };
        served += 1;
        let delay = match answers.verdict(&question, rng) {
            Verdict::Drop => continue,
            Verdict::Answer => Duration::ZERO,
            Verdict::Delay(delay) => delay,
        };
        let len = u16::try_from(reply.len()).expect("a reply fits the buffer of OUT bytes");
        let mut framed = len.to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        let (writer, trace) = (Rc::clone(&writer), trace.clone());
        delayed.spawn_local(async move {
            tokio::time::sleep(delay).await;
            trace.record(
                host,
                What::Served {
                    question,
                    transport,
                },
            );
            // A closed connection loses the response, as a server's does.
            let _ = writer.lock().await.write_all(framed).await;
        });
    }
    // A response task that panicked panics the connection's, which fails the run (`Port::next`).
    while let Some(done) = delayed.join_next().await {
        if let Err(error) = done
            && error.is_panic()
        {
            std::panic::resume_unwind(error.into_panic());
        }
    }
    writer.lock().await.close().await;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use dedens_proto::RecordType;

    use super::*;
    use crate::seed::Seed;
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
    fn a_derived_response_goes_ahead_of_the_captures_with_the_queries_id() {
        let held = ask("example.com", RecordType::A);
        let made = captured("txt_large");
        let asked = held.clone();
        let answers = Answers::new().captured("a").derived(move |question| {
            // For the question the captures hold, and for no other: the capture's own answer comes for the rest.
            (*question == asked).then(|| made.clone())
        });
        let (reply, _) = answers
            .reply(&query(held, Some(4096), None), Transport::Udp)
            .expect("a reply");
        assert_eq!(reply.get(..2), Some([0x12, 0x34].as_slice()));
        assert_eq!(reply.get(2..), captured("txt_large").get(2..));
        let other = ask("nothing.example", RecordType::A);
        let (reply, _) = answers
            .reply(&query(other, Some(1232), None), Transport::Udp)
            .expect("a reply");
        assert_eq!(decode(&reply).rcode(), Rcode::REFUSED);
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
        // Room enough, or a stream (RFC 7766 §8, RFC 7858 §3.3): the capture, with the ID of the query.
        for (payload, transport) in [
            (4096, Transport::Udp),
            (512, Transport::Tcp),
            (512, Transport::Tls),
        ] {
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
    fn signatures_come_only_to_a_query_with_do() {
        let dir = dedens_testkit::path("dnssec");
        let answers = Answers::new().directory(&dir);
        // Whether the response holds data, and whether it holds signatures or proofs, in any section.
        let got = |name: &str, do_bit: bool| {
            let mut message = Message::query(0x1234, ask(name, RecordType::A));
            let edns = message.edns.as_mut().expect("EDNS");
            edns.flags = if do_bit {
                EdnsFlags::DO
            } else {
                EdnsFlags::default()
            };
            let mut out = vec![0; OUT];
            let len = message.encode(&mut out).expect("encodes");
            out.truncate(len);
            let (reply, _) = answers.reply(&out, Transport::Tcp).expect("a reply");
            let reply = decode(&reply);
            let records = || {
                reply
                    .answer
                    .iter()
                    .chain(&reply.authority)
                    .chain(&reply.additional)
            };
            let signed = |record: &&dedens_proto::Record<'_>| {
                matches!(
                    record.rtype(),
                    RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                )
            };
            (
                records().any(|record| !signed(&record)),
                records().any(|record| signed(&record)),
            )
        };
        // The signatures are in the answer section, or the proofs in the authority one.
        for name in ["cloudflare.com", "xyzzy-nonexistent-tld"] {
            assert_eq!(got(name, true), (true, true), "{name}");
            assert_eq!(got(name, false), (true, false), "{name}");
        }
    }

    #[test]
    fn a_directory_holds_the_first_response_of_each_question() {
        let dir = dedens_testkit::path("dnssec");
        let answers = Answers::new().directory(&dir);
        let count = answers.expected().count();
        assert!(count > 100, "{count}");
        let all = answers.entries.len();
        assert_eq!(answers.directory(&dir).entries.len(), all, "twice the same");
    }

    /// One UDP response in `one_in` is lost: the first among the first `one_in`, as the seed draws, then every
    /// `one_in`-th; a response the server drops anyway is not counted (D196).
    #[test]
    fn a_lossy_server_loses_every_one_in_th_udp_response() {
        const ONE_IN: usize = 4;
        let one_in = NonZeroU64::new(4).expect("not zero");
        let question = txt();
        let mut firsts = BTreeSet::new();
        for seed in 0..16 {
            let rng = RefCell::new(Rng::new(Seed(seed), 0));
            // Every other response dropped by the server.
            let odd = Cell::new(false);
            let answers = Answers::new().lossy(one_in).faulty(move |_, _| {
                odd.set(!odd.get());
                if odd.get() {
                    Verdict::Answer
                } else {
                    Verdict::Drop
                }
            });
            // The responses the server sends, each lost or not.
            let lost: Vec<bool> = (0..2 * 3 * ONE_IN)
                .map(|_| answers.udp_verdict(&question, &rng) == Verdict::Drop)
                .collect::<Vec<_>>()
                .chunks(2)
                .map(|pair| pair[0])
                .collect();
            let first = lost.iter().position(|&lost| lost).expect("one lost");
            firsts.insert(first);
            let every: Vec<bool> = (0..3 * ONE_IN)
                .map(|at| at >= first && (at - first) % ONE_IN == 0)
                .collect();
            assert_eq!(lost, every, "seed {seed}");
        }
        assert_eq!(firsts.len(), ONE_IN, "{firsts:?}");
    }
}
