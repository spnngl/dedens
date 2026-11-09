//! Running the queries of the command line or of a query file: at most [`IN_FLIGHT`] at a time, each result
//! printed in order as soon as it is ready. The servers they go to are chosen in the `server` module.

mod server;

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;

use anyhow::{Context, anyhow, bail};
use compio::quic::ConnectionError;
use compio::quic::h3::error::ConnectionError as H3Error;
use dedens_dnssec::covered;
use dedens_net::client::{Client, ClientError, Server};
#[cfg(feature = "doc")]
use dedens_net::doc::DocError;
use dedens_net::exchange::{self, Failure, Response};
use dedens_net::http3::Http3Error;
use dedens_net::quic::QuicError;
use dedens_net::tcp::TcpError;
use dedens_proto::{Class, Message, Name, Question, Rcode, RecordType, Transport};
use dedens_scenario::{DnssecStatus, Expect, Id, Latency, Options, QueryFile, Report};

pub(crate) use self::server::refuse_conflicts;
use self::server::{resolv_conf, server, servers};
use crate::args::{self, Cli};
use crate::idn;
use crate::output::{self, Format, Printing};
use crate::trace::{self, Trail};
use crate::validate::{Judge, Judges};

/// The queries in flight at most: each holds a socket.
const IN_FLIGHT: usize = 64;

/// One query to ask.
struct Job {
    id: Id,
    /// The names to try in order, the next one after an NXDOMAIN (`+search`); never empty.
    names: Vec<Name<'static>>,
    qtype: RecordType,
    qclass: Class,
    route: Route,
    options: Options,
    expect: Option<Expect>,
    /// Set for a query that validates (`+validate`): its validator, which queries with the same anchors share.
    judge: Option<Judge>,
}

/// Where a query goes.
#[derive(Clone)]
enum Route {
    /// To each of these servers, side by side; never empty, without duplicates.
    Servers(Vec<Endpoint>),
    /// From these root servers down the referrals (`+trace`).
    Trace(Rc<[SocketAddr]>),
}

/// A server of the command line or of a query file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    server: Server,
    /// The transport whatever the options say: given as `tls://`, `quic://` or `https://`, or Oblivious `DoH`, which
    /// `+odoh-proxy` makes of an `https://` server (D79).
    forced: Option<Transport>,
    /// The proxy of Oblivious `DoH`, `server` being the target.
    proxy: Option<Box<Server>>,
}

impl Endpoint {
    /// The id of query `id` asked of this server, one of several: `example.com_A@1.1.1.1`, `+tls`, `+quic` or
    /// `+https` or `+coap` after it when forced, so `tls://`, `quic://`, `https://` and `coap://` to one address stay apart.
    fn id(&self, id: &Id) -> Id {
        let id = id.at(self.server.addr);
        let over = match self.forced {
            Some(Transport::Tls) => "tls",
            Some(Transport::Quic) => "quic",
            Some(Transport::Https) => "https",
            Some(Transport::Odoh) => "odoh",
            Some(Transport::Coap) => "coap",
            _ => return id,
        };
        Id::try_from(format!("{id}+{over}")).expect("an id with letters after it stays an id")
    }
}

impl Route {
    /// Whether the query goes to several servers, whose answers are compared.
    fn several(&self) -> bool {
        matches!(self, Self::Servers(servers) if servers.len() > 1)
    }
}

/// Runs `cli`; an error is one of the run as a whole, before any query or while printing.
pub(crate) fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    let mut jobs = match &cli.file {
        Some(path) => file_jobs(cli, path)?,
        None => command_line_jobs(cli)?,
    };
    let mut judges = Judges::new()?;
    for job in &mut jobs {
        job.judge = judges.of(&job.options)?;
    }
    if let Some(job) = jobs
        .iter()
        .find(|job| matches!(job.qtype, RecordType::AXFR | RecordType::IXFR))
    {
        bail!("{}: zone transfers are not supported yet", job.id);
    }
    if let Some(dir) = &cli.save_wire {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let format = cli.output.format();
    let mut out = anstream::AutoStream::new(io::stdout().lock(), cli.output.color());
    let trust = cli.trust()?;
    let runtime = compio::runtime::Runtime::new().context("cannot start the runtime")?;
    let code = runtime.block_on(async {
        let client = Rc::new(Client::new().trusting(trust));
        // One task per job and server, the servers of a job one after the other: a group.
        let mut tasks = jobs.into_iter().enumerate().flat_map(|(group, job)| {
            let job = Rc::new(job);
            let servers = match &job.route {
                Route::Servers(servers) => servers.iter().cloned().map(Target::Server).collect(),
                Route::Trace(roots) => vec![Target::Trace(Rc::clone(roots))],
            };
            servers
                .into_iter()
                .map(move |target| (group, Rc::clone(&job), target))
        });
        let mut running = VecDeque::new();
        let (mut code, mut printed) = (0, false);
        // The answers of the group being printed, compared once it is all printed.
        let (mut group_now, mut answers) = (None, Vec::new());
        loop {
            let room = IN_FLIGHT - running.len();
            running.extend(tasks.by_ref().take(room).map(|(group, job, target)| {
                let id = match &target {
                    Target::Server(endpoint) if job.route.several() => endpoint.id(&job.id),
                    _ => job.id.clone(),
                };
                let task = query(
                    Rc::clone(&client),
                    Rc::clone(&job),
                    target,
                    id.clone(),
                    cli.repeat,
                );
                (group, job, id, compio::runtime::spawn(task))
            }));
            let next = running.pop_front();
            if next.as_ref().map(|(group, ..)| *group) != group_now {
                output::disagreement(&mut out, &answers)?;
                answers.clear();
                group_now = next.as_ref().map(|(group, ..)| *group);
            }
            let Some((_, job, id, handle)) = next else {
                break;
            };
            let trail = handle
                .await
                .unwrap_or_else(|e| (Vec::new(), Some(io::Error::from(e).into())));
            if job.route.several() && format == Format::Human {
                answers.extend(trail.0.iter().filter_map(|(report, _)| {
                    let server = report.exchange.as_ref()?.server;
                    Some((server, output::Answers::of(report)))
                }));
            }
            let printing = Printing {
                format,
                trace: matches!(job.route, Route::Trace(_)),
            };
            code = code.max(show(cli, printing, &mut out, &id, trail, &mut printed)?);
        }
        io::Result::Ok(code)
    })?;
    Ok(ExitCode::from(code))
}

/// Prints the responses of query `id` and saves them, then the error that ended it; returns the exit code they
/// call for. `printed` tells whether a report came before, which the human format sets apart.
fn show(
    cli: &Cli,
    printing: Printing,
    out: &mut impl Write,
    id: &Id,
    (reports, error): Trail,
    printed: &mut bool,
) -> io::Result<u8> {
    let mut code = 0;
    for (report, wire) in reports {
        if std::mem::replace(printed, true) && printing.format == Format::Human {
            writeln!(out)?;
        }
        output::print(out, printing, &report, &wire)?;
        out.flush()?;
        if printing.format == Format::Short {
            for line in report.violations.iter().chain(&report.failures) {
                eprintln!("dedens: {}: {line}", report.id);
            }
            // Short output is the answer's data: a failed verdict must not pass unseen (D76).
            for dnssec in report
                .dnssec
                .iter()
                .filter(|d| matches!(d.status, DnssecStatus::Bogus | DnssecStatus::Indeterminate))
            {
                let ede = dnssec
                    .ede
                    .iter()
                    .map(|e| format!(" (EDE {}: {})", e.code, e.text));
                eprintln!(
                    "dedens: {}: dnssec {}{}",
                    report.id,
                    dnssec.status,
                    ede.collect::<String>()
                );
            }
        }
        code = code.max(u8::from(!report.failures.is_empty()));
        if let Some(dir) = &cli.save_wire {
            let path = dir.join(format!("{}.bin", report.id));
            if let Err(error) = std::fs::write(&path, wire) {
                eprintln!("dedens: cannot write {}: {error}", path.display());
                code = 10;
            }
        }
    }
    if let Some(error) = error {
        eprintln!("dedens: {id}: {error:#}");
        code = code.max(if no_reply(&error) { 9 } else { 10 });
    }
    Ok(code)
}

/// The root servers of `+trace` from `DEDENS_ROOTS`, addresses with ports separated by commas (for tests); else
/// the root hints.
fn roots() -> anyhow::Result<Rc<[SocketAddr]>> {
    let Some(text) = std::env::var_os("DEDENS_ROOTS") else {
        return Ok(trace::root_hints().into());
    };
    let text = text.to_string_lossy();
    let roots = text.split(',').map(str::parse).collect::<Result<_, _>>();
    roots.with_context(|| format!("DEDENS_ROOTS={text}"))
}

/// Where one task sends a query.
enum Target {
    Server(Endpoint),
    /// The root servers of `+trace`.
    Trace(Rc<[SocketAddr]>),
}

/// Asks `job` of a server `times` in a row (see [`repeat`]), or traces it from the roots.
async fn query(client: Rc<Client>, job: Rc<Job>, target: Target, id: Id, times: u16) -> Trail {
    let endpoint = match target {
        Target::Server(endpoint) => endpoint,
        Target::Trace(roots) => {
            let question = Question {
                name: job.names[0].clone(),
                qtype: job.qtype,
                qclass: job.qclass,
            };
            return trace::trace(&client, job.options.clone(), question, &id, &roots).await;
        }
    };
    match repeat(&client, &job, &endpoint, id, times).await {
        Ok(answered) => (vec![answered], None),
        Err(error) => (Vec::new(), Some(error)),
    }
}

/// Asks `job` of `server` `times` in a row; the last response, with the latency of all when more than one, else
/// the last error.
async fn repeat(
    client: &Client,
    job: &Job,
    endpoint: &Endpoint,
    id: Id,
    times: u16,
) -> anyhow::Result<(Report, Vec<u8>)> {
    let mut rtts = Vec::with_capacity(times.into());
    let mut last = Err(anyhow!("not asked"));
    for _ in 0..times {
        match ask(client, job, endpoint, id.clone()).await {
            Ok(answered) => {
                rtts.extend(answered.0.exchange.as_ref().map(|exchange| exchange.rtt_us));
                last = Ok(answered);
            }
            Err(error) if last.is_err() => last = Err(error),
            Err(_) => {}
        }
    }
    if let Ok((report, _)) = &mut last
        && times > 1
    {
        report.latency = Latency::of(times, &mut rtts);
    }
    last
}

/// Asks `job` of `endpoint`, trying its names in turn while the response is NXDOMAIN; `id` names the report, which
/// holds what the response breaks of the job's expectations.
async fn ask(
    client: &Client,
    job: &Job,
    endpoint: &Endpoint,
    id: Id,
) -> anyhow::Result<(Report, Vec<u8>)> {
    let mut options = job.options.exchange();
    if let Some(transport) = endpoint.forced {
        options.transport = transport;
    }
    let address = endpoint.server.addr;
    let (found, doc_path) = discovered(client, job, endpoint, options.transport).await?;
    let endpoint = &*found;
    let with_path = |mut report: Report| {
        if let Some(exchange) = &mut report.exchange {
            exchange.doc_path.clone_from(&doc_path);
        }
        report
    };
    #[cfg(feature = "odoh")]
    if endpoint.proxy.is_some()
        && let Some(file) = &job.options.odoh_config
    {
        let configs = std::fs::read(file)
            .with_context(|| format!("+odoh-config {file}: cannot read the file"))?;
        client
            .pin_odoh_configs(endpoint.server.clone(), &configs)
            .with_context(|| format!("+odoh-config {file}: not key configurations"))?;
    }
    for (index, name) in job.names.iter().enumerate() {
        let question = Question {
            name: name.clone(),
            qtype: job.qtype,
            qclass: job.qclass,
        };
        let query = job.options.query(question.clone());
        let response = exchange(client, endpoint, query, &options).await?;
        let decoded = Message::decode(&response.wire)?;
        if index + 1 == job.names.len() || decoded.message.rcode() != Rcode::NXDOMAIN {
            let dnssec = match &job.judge {
                // The verdict is on the response; its questions go to the same server, the same way.
                Some(judge) => {
                    let send =
                        async |query| Ok(exchange(client, endpoint, query, &options).await?.wire);
                    Some(
                        judge
                            .judge(&job.options, &question, &decoded.message, send)
                            .await,
                    )
                }
                None => None,
            };
            let status = dnssec.as_ref().map(|dnssec| dnssec.status);
            // Only a secure verdict is shown as covering the response, and then only what it covers (D76): the
            // expectations see what is shown.
            let mut shown = decoded;
            if status == Some(DnssecStatus::Secure) {
                shown.message = covered(&shown.message);
            }
            let failures = job.expect.as_ref().map_or_else(Vec::new, |expect| {
                let mut failures = expect.check(&shown.message);
                failures.extend(expect.check_dnssec(status));
                failures
            });
            let report = Report {
                dnssec,
                failures,
                ..Report::exchanged(id, address, &response, &shown)
            };
            return Ok((with_path(report), response.wire));
        }
    }
    Err(anyhow!("no name to ask"))
}

/// `endpoint`, and with `+doc-discover` the path of its `DoC` resource, the first its `/.well-known/core` lists
/// with the resource type `core.dns` (RFC 9953 §3.1, D95), as a URI path. The server is the one named: never
/// found, so what it lists is as trusted as it is (§3).
async fn discovered<'a>(
    client: &Client,
    job: &Job,
    endpoint: &'a Endpoint,
    transport: Transport,
) -> anyhow::Result<(Cow<'a, Endpoint>, Option<String>)> {
    if job.options.doc_discover != Some(true) {
        return Ok((Cow::Borrowed(endpoint), None));
    }
    let address = endpoint.server.addr;
    if transport != Transport::Coap || !endpoint.server.docpath.is_empty() {
        bail!("server {address}: +doc-discover needs a CoAP server with no path");
    }
    let paths = client
        .discover_doc(address)
        .await
        .with_context(|| format!("server {address}: +doc-discover"))?;
    let Some(path) = paths.into_iter().next() else {
        bail!("server {address}: no resource of type core.dns in its /.well-known/core");
    };
    let text = path.iter().fold(String::new(), |text, segment| {
        format!("{text}/{}", String::from_utf8_lossy(segment))
    });
    let mut found = endpoint.clone();
    found.server.docpath = path;
    Ok((
        Cow::Owned(found),
        Some(if text.is_empty() {
            "/".to_owned()
        } else {
            text
        }),
    ))
}

/// Tells on stderr what the Oblivious `DoH` exchanges since the last call have to tell (D79).
#[cfg(feature = "odoh")]
fn notices(client: &Client) {
    for notice in client.take_odoh_notices() {
        let message = match notice {
            dedens_net::odoh::Notice::ConfigsNotToBeKept(target) => format!(
                "{target} was asked for its key configurations from this address, not through the proxy, and does not want them kept: \
                 it can link the address to the query that follows; +odoh-config=FILE avoids the fetch"
            ),
            _ => continue,
        };
        // Nowhere to report a stderr that does not write.
        let _ = writeln!(io::stderr(), "warning: {message}");
    }
}

/// Sends `query` to `endpoint`, over the transport of `options`, through its proxy when it has one.
async fn exchange(
    client: &Client,
    endpoint: &Endpoint,
    query: Message<'_>,
    options: &exchange::Options,
) -> Result<Response, ClientError> {
    let server = endpoint.server.clone();
    match &endpoint.proxy {
        #[cfg(feature = "odoh")]
        Some(proxy) => {
            let response = client
                .exchange_oblivious(query, server, Some(Server::clone(proxy)), options)
                .await;
            notices(client);
            response
        }
        _ => client.exchange(query, server, options).await,
    }
}

/// Whether `error` is the server's silence, refusal or reset: dig's exit code 9.
fn no_reply(error: &anyhow::Error) -> bool {
    let refused = |e: &io::Error| {
        matches!(
            e.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
        )
    };
    match error.downcast_ref() {
        Some(
            ClientError::Exchange(Failure::TimedOut { .. } | Failure::Forged { .. })
            | ClientError::Tcp(TcpError::TimedOut | TcpError::Closed)
            | ClientError::Quic(
                QuicError::TimedOut | QuicError::Connection(ConnectionError::TimedOut),
            )
            | ClientError::Https(
                Http3Error::TimedOut
                | Http3Error::Connection(H3Error::Timeout)
                | Http3Error::Quic(
                    QuicError::TimedOut | QuicError::Connection(ConnectionError::TimedOut),
                ),
            ),
        ) => true,
        #[cfg(feature = "doc")]
        Some(ClientError::Doc(DocError::Exchange(
            dedens_net::coap::exchange::Failure::TimedOut,
        ))) => true,
        #[cfg(feature = "doc")]
        Some(ClientError::Doc(DocError::Udp(e))) => refused(e),
        Some(
            ClientError::Udp(e) | ClientError::Tcp(TcpError::Connect(e) | TcpError::Handshake(e)),
        ) => refused(e),
        _ => false,
    }
}

/// The queries of the command line: its words (see [`args::lookups`]), then the `-x` addresses asked PTR.
fn command_line_jobs(cli: &Cli) -> anyhow::Result<Vec<Job>> {
    let (lookups, qclass) = args::lookups(&cli.words, !cli.reverse.is_empty());
    let conf = (cli.search || (cli.servers().is_empty() && !cli.trace))
        .then(resolv_conf)
        .transpose()?;
    let route = match servers(cli, conf.as_ref(), &cli.options)? {
        _ if cli.trace => Route::Trace(roots()?),
        servers if servers.is_empty() => {
            Route::Servers(vec![server(None, conf.as_ref(), cli.port, &cli.options)?])
        }
        servers => Route::Servers(servers),
    };
    let job = |names: Vec<Name<'static>>, qtype| Job {
        id: Id::of(&names[0], qtype),
        names,
        qtype,
        qclass,
        route: route.clone(),
        options: cli.options.clone(),
        expect: None,
        judge: None,
    };
    let mut jobs = Vec::new();
    for (text, types) in lookups {
        let (ascii, warnings) =
            idn::to_ascii(text).map_err(|e| anyhow!("{text}: not a domain name: {e}"))?;
        for warning in warnings {
            eprintln!("dedens: warning: {warning}");
        }
        let candidates = match (&conf, cli.search) {
            (Some(conf), true) => conf.candidates(&ascii),
            _ => ascii.parse().ok().map(|name| vec![name]),
        };
        let candidates = candidates.ok_or_else(|| anyhow!("{text}: not a domain name"))?;
        jobs.extend(
            types
                .into_iter()
                .map(|qtype| job(candidates.clone(), qtype)),
        );
    }
    for &address in &cli.reverse {
        jobs.push(job(vec![Name::reverse(address)], RecordType::PTR));
    }
    Ok(jobs)
}

/// The queries of the file of `-f`, with the options of the command line over theirs.
fn file_jobs(cli: &Cli, path: &Path) -> anyhow::Result<Vec<Job>> {
    let mut text = String::new();
    if path == Path::new("-") {
        io::stdin().read_to_string(&mut text)?;
    } else {
        text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
    }
    let file = QueryFile::parse(&text).with_context(|| format!("{}", path.display()))?;
    if let Some(id) = cli
        .only
        .iter()
        .find(|id| !file.queries.iter().any(|q| q.id() == **id))
    {
        bail!("{}: no query with id {id}", path.display());
    }
    let missing = file.server.is_none() && file.queries.iter().any(|q| q.server.is_none());
    let conf = (cli.servers().is_empty() && missing)
        .then(resolv_conf)
        .transpose()?;
    file.queries
        .into_iter()
        .filter(|q| cli.only.is_empty() || cli.only.contains(&q.id()))
        .map(|query| {
            let id = query.id();
            let options = cli
                .options
                .clone()
                .or(query.options)
                .or(file.options.clone());
            options.check().with_context(|| format!("{id}"))?;
            if query
                .expect
                .as_ref()
                .is_some_and(|expect| expect.dnssec.is_some())
                && !options.validating()
            {
                bail!("{id}: the dnssec expectation needs the validate option");
            }
            let named = query.server.as_deref().or(file.server.as_deref());
            Ok(Job {
                route: Route::Servers(match servers(cli, conf.as_ref(), &options)? {
                    servers if servers.is_empty() => {
                        vec![server(named, conf.as_ref(), cli.port, &options)?]
                    }
                    servers => servers,
                }),
                id,
                names: vec![query.name],
                qtype: query.qtype,
                qclass: Class::IN,
                options,
                expect: query.expect,
                judge: None,
            })
        })
        .collect()
}
