//! Running the queries of the command line or of a query file: at most [`IN_FLIGHT`] at a time, each result
//! printed in order as soon as it is ready.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use anyhow::{Context, anyhow, bail};
use compio::quic::ConnectionError;
use compio::quic::h3::error::ConnectionError as H3Error;
use compio::rustls::pki_types::ServerName;
use dedens_net::client::{Client, ClientError, Server};
use dedens_net::doh::{DEFAULT_PATH, Template};
use dedens_net::exchange::{Failure, Transport};
use dedens_net::https::HttpsError;
use dedens_net::quic::QuicError;
use dedens_net::resolv_conf::ResolvConf;
use dedens_net::tcp::TcpError;
use dedens_proto::{Class, Message, Name, Question, Rcode, RecordType};
use dedens_scenario::{Expect, Id, Latency, Options, QueryFile, Report};

use crate::args::{self, Cli};
use crate::idn;
use crate::output::{self, Format, Printing};
use crate::trace::{self, Trail};

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
    /// The transport whatever the options say: given as `tls://`, `quic://` or `https://`.
    forced: Option<Transport>,
}

impl Endpoint {
    /// The id of query `id` asked of this server, one of several: `example.com_A@1.1.1.1`, `+tls`, `+quic` or
    /// `+https` after it when forced, so `tls://`, `quic://` and `https://` to one address stay apart.
    fn id(&self, id: &Id) -> Id {
        let id = id.at(self.server.addr);
        let over = match self.forced {
            Some(Transport::Tls) => "tls",
            Some(Transport::Quic) => "quic",
            Some(Transport::Https) => "https",
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
    let jobs = match &cli.file {
        Some(path) => file_jobs(cli, path)?,
        None => command_line_jobs(cli)?,
    };
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
    let color = match cli.output.color {
        clap::ColorChoice::Auto => anstream::ColorChoice::Auto,
        clap::ColorChoice::Always => anstream::ColorChoice::Always,
        clap::ColorChoice::Never => anstream::ColorChoice::Never,
    };
    let mut out = anstream::AutoStream::new(io::stdout().lock(), color);
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
                rtts.extend(answered.0.exchange.map(|exchange| exchange.rtt_us));
                last = Ok(answered);
            }
            Err(error) if last.is_err() => last = Err(error),
            Err(_) => {}
        }
    }
    if let Ok((report, wire)) = &mut last {
        if times > 1 {
            report.latency = Latency::of(times, &mut rtts);
        }
        if let Some(expect) = &job.expect {
            report.failures = expect.check(&Message::decode(wire)?.message);
        }
    }
    last
}

/// Asks `job` of `endpoint`, trying its names in turn while the response is NXDOMAIN; `id` names the report.
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
    let server = endpoint.server.addr;
    for (index, name) in job.names.iter().enumerate() {
        let question = Question {
            name: name.clone(),
            qtype: job.qtype,
            qclass: job.qclass,
        };
        let response = client
            .exchange(
                job.options.query(question),
                endpoint.server.clone(),
                &options,
            )
            .await?;
        let decoded = Message::decode(&response.wire)?;
        if index + 1 == job.names.len() || decoded.message.rcode() != Rcode::NXDOMAIN {
            let report = Report::exchanged(id, server, &response, &decoded);
            return Ok((report, response.wire));
        }
    }
    Err(anyhow!("no name to ask"))
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
                HttpsError::TimedOut
                | HttpsError::Connection(H3Error::Timeout)
                | HttpsError::Quic(
                    QuicError::TimedOut | QuicError::Connection(ConnectionError::TimedOut),
                ),
            ),
        ) => true,
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
    let route = match servers(cli, conf.as_ref())? {
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
    let servers = servers(cli, conf.as_ref())?;
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
            let named = query.server.as_deref().or(file.server.as_deref());
            Ok(Job {
                route: Route::Servers(match &servers {
                    servers if servers.is_empty() => {
                        vec![server(named, conf.as_ref(), cli.port, &options)?]
                    }
                    servers => servers.clone(),
                }),
                id,
                names: vec![query.name],
                qtype: query.qtype,
                qclass: Class::IN,
                options,
                expect: query.expect,
            })
        })
        .collect()
}

/// The resolver configuration, from `DEDENS_RESOLV_CONF` when set (for tests), else /etc/resolv.conf.
fn resolv_conf() -> anyhow::Result<ResolvConf> {
    let path = std::env::var_os("DEDENS_RESOLV_CONF")
        .map_or_else(|| PathBuf::from("/etc/resolv.conf"), PathBuf::from);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(ResolvConf::parse(&text))
}

/// The servers of the command line, in order, each once.
fn servers(cli: &Cli, conf: Option<&ResolvConf>) -> anyhow::Result<Vec<Endpoint>> {
    let mut servers = Vec::new();
    for named in cli.servers() {
        let address = server(Some(named), conf, cli.port, &cli.options)?;
        if !servers.contains(&address) {
            servers.push(address);
        }
    }
    Ok(servers)
}

/// The port of DNS over TLS (RFC 7858 §3.1) and over QUIC (RFC 9250 §4.1.1).
const ENCRYPTED_PORT: u16 = 853;

/// The port of DNS over HTTPS (RFC 8484 §3, RFC 9110 §4.2.2).
const HTTPS_PORT: u16 = 443;

/// `named`, else the first name server of `conf`: an address, IPv6 possibly in brackets or with its zone, or a
/// host name, each with or without a port; `tls://` or `quic://` before it for TLS or QUIC, `https://` and a path
/// after it for DNS over HTTPS (else the path of `options`, else `/dns-query`), and `#NAME` after it for the name the
/// server's certificate must hold, else its host name, else its address. Without a port, `port`, else 443 over
/// HTTPS, else 853 over TLS or QUIC (`options` or a scheme), else 53.
fn server(
    named: Option<&str>,
    conf: Option<&ResolvConf>,
    port: Option<u16>,
    options: &Options,
) -> anyhow::Result<Endpoint> {
    let text = match named {
        Some(text) => text,
        None => conf
            .and_then(|conf| conf.nameservers.first())
            .ok_or_else(|| {
                anyhow!("no server: give @server, or a nameserver in /etc/resolv.conf")
            })?,
    };
    let given = text;
    let (text, forced) = [
        ("tls://", Transport::Tls),
        ("quic://", Transport::Quic),
        ("https://", Transport::Https),
    ]
    .into_iter()
    .find_map(|(scheme, transport)| Some((text.strip_prefix(scheme)?, Some(transport))))
    .unwrap_or((text, None));
    let (text, name) = match text.rsplit_once('#') {
        Some((text, name)) => (text, Some(name)),
        None => (text, None),
    };
    let https = forced == Some(Transport::Https);
    let (text, url_path) = match text.split_once('/') {
        Some((host, path)) if https => (host, Some(format!("/{path}"))),
        _ => (text, None),
    };
    let doh = https || options.https();
    let encrypted = forced.is_some() || options.encrypted() || doh;
    // `[HOST]:PORT`, `[HOST]`, `HOST:PORT` with a single colon, else the host alone: an IPv6 address among them.
    let (host, written) = match text.strip_prefix('[').and_then(|text| text.split_once(']')) {
        Some((host, "")) => (host, None),
        Some((host, port)) => (host, Some(port.strip_prefix(':').unwrap_or(port))),
        None => match text.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            _ => (text, None),
        },
    };
    let port = match written {
        Some(written) => written
            .parse()
            .with_context(|| format!("server {given}: not a port"))?,
        None => port.unwrap_or(match (doh, encrypted) {
            (true, _) => HTTPS_PORT,
            (_, true) => ENCRYPTED_PORT,
            _ => 53,
        }),
    };
    // An address, its zone aside, has no name to check.
    let literal = host
        .split_once('%')
        .map_or(host, |(address, _)| address)
        .parse::<IpAddr>()
        .is_ok();
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        // A host name, or an address with its zone, which the system resolver reads.
        Err(_) => (host, port)
            .to_socket_addrs()
            .with_context(|| format!("server {given}"))?
            .next()
            .ok_or_else(|| anyhow!("server {given}: no address"))?,
    };
    let name = name
        .or((!literal).then_some(host))
        .filter(|_| encrypted)
        .map(|name| ServerName::try_from(name.to_owned()))
        .transpose()
        .with_context(|| format!("server {given}: not a name for TLS"))?;
    let template = doh
        .then(|| {
            let path = url_path
                .as_deref()
                .or(options.https_path())
                .unwrap_or(DEFAULT_PATH);
            let brackets = if host.contains(':') {
                ("[", "]")
            } else {
                ("", "")
            };
            let port = if port == HTTPS_PORT {
                String::new()
            } else {
                format!(":{port}")
            };
            Template::parse(&format!(
                "https://{}{host}{}{port}{path}",
                brackets.0, brackets.1
            ))
            .with_context(|| format!("server {given}"))
        })
        .transpose()?;
    Ok(Endpoint {
        server: Server {
            addr,
            name,
            doh: template,
        },
        forced,
    })
}
