//! Running the queries of the command line or of a query file: at most [`IN_FLIGHT`] at a time, each result
//! printed in order as soon as it is ready.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use anyhow::{Context, anyhow, bail};
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::Failure;
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
    /// To each of these servers, side by side; never empty.
    Servers(Vec<SocketAddr>),
    /// From the root servers down the referrals (`+trace`).
    Trace,
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
    let roots = roots()?;
    let runtime = compio::runtime::Runtime::new().context("cannot start the runtime")?;
    let code = runtime.block_on(async {
        let client = Rc::new(Client::new());
        // One task per job and server, the servers of a job one after the other: a group.
        let mut tasks = jobs.into_iter().enumerate().flat_map(|(group, job)| {
            let job = Rc::new(job);
            let servers = match &job.route {
                Route::Servers(servers) => servers.iter().copied().map(Some).collect(),
                Route::Trace => vec![None],
            };
            let several = servers.len() > 1;
            servers
                .into_iter()
                .map(move |server| (group, several, Rc::clone(&job), server))
        });
        let mut running = VecDeque::new();
        let (mut code, mut printed) = (0, false);
        // The answers of the group being printed, compared once it is all printed.
        let (mut group_now, mut answers) = (None, Vec::new());
        loop {
            let room = IN_FLIGHT - running.len();
            running.extend(
                tasks
                    .by_ref()
                    .take(room)
                    .map(|(group, several, job, server)| {
                        let id = match server {
                            Some(server) if several => job.id.at(server),
                            _ => job.id.clone(),
                        };
                        let task = query(
                            Rc::clone(&client),
                            job,
                            server,
                            id.clone(),
                            cli.repeat,
                            roots.clone(),
                        );
                        (
                            group,
                            several,
                            server.is_none(),
                            id,
                            compio::runtime::spawn(task),
                        )
                    }),
            );
            let next = running.pop_front();
            if next.as_ref().map(|(group, ..)| *group) != group_now {
                if format == Format::Human {
                    output::disagreement(&mut out, &answers)?;
                }
                answers.clear();
                group_now = next.as_ref().map(|(group, ..)| *group);
            }
            let Some((_, several, traced, id, handle)) = next else {
                break;
            };
            let trail = handle
                .await
                .unwrap_or_else(|e| (Vec::new(), Some(io::Error::from(e).into())));
            if several {
                answers.extend(trail.0.iter().filter_map(|(report, _)| {
                    let server = report.exchange.as_ref()?.server;
                    Some((server, output::Answers::of(report)))
                }));
            }
            let printing = Printing {
                format,
                brief: traced,
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
        output::print(out, printing, &report)?;
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
fn roots() -> anyhow::Result<Option<Vec<SocketAddr>>> {
    let Some(text) = std::env::var_os("DEDENS_ROOTS") else {
        return Ok(None);
    };
    let text = text.to_string_lossy();
    let roots = text.split(',').map(str::parse).collect::<Result<_, _>>();
    Ok(Some(roots.with_context(|| format!("DEDENS_ROOTS={text}"))?))
}

/// Asks `job` of `server` `times` in a row (see [`repeat`]), or traces it from `roots` without a server.
async fn query(
    client: Rc<Client>,
    job: Rc<Job>,
    server: Option<SocketAddr>,
    id: Id,
    times: u16,
    roots: Option<Vec<SocketAddr>>,
) -> Trail {
    let Some(server) = server else {
        let question = Question {
            name: job.names[0].clone(),
            qtype: job.qtype,
            qclass: job.qclass,
        };
        return trace::trace(&client, job.options, question, &id, roots).await;
    };
    match repeat(&client, &job, server, id, times).await {
        Ok(answered) => (vec![answered], None),
        Err(error) => (Vec::new(), Some(error)),
    }
}

/// Asks `job` of `server` `times` in a row; the last response, with the latency of all when more than one, else
/// the last error.
async fn repeat(
    client: &Client,
    job: &Job,
    server: SocketAddr,
    id: Id,
    times: u16,
) -> anyhow::Result<(Report, Vec<u8>)> {
    let mut rtts = Vec::with_capacity(times.into());
    let mut last = Err(anyhow!("not asked"));
    for _ in 0..times {
        match ask(client, job, server, id.clone()).await {
            Ok(answered) => {
                rtts.extend(answered.0.exchange.map(|exchange| exchange.rtt_us));
                last = Ok(answered);
            }
            Err(error) if last.is_err() => last = Err(error),
            Err(_) => {}
        }
    }
    if times > 1
        && let Ok((report, _)) = &mut last
    {
        report.latency = Latency::of(times, &mut rtts);
    }
    last
}

/// Asks `job` of `server`, trying its names in turn while the response is NXDOMAIN; `id` names the report.
async fn ask(
    client: &Client,
    job: &Job,
    server: SocketAddr,
    id: Id,
) -> anyhow::Result<(Report, Vec<u8>)> {
    let options = job.options.exchange();
    for (index, name) in job.names.iter().enumerate() {
        let question = Question {
            name: name.clone(),
            qtype: job.qtype,
            qclass: job.qclass,
        };
        let response = client
            .exchange(&job.options.query(question), server, &options)
            .await?;
        let decoded = Message::decode(&response.wire)?;
        if index + 1 == job.names.len() || decoded.message.rcode() != Rcode::NXDOMAIN {
            let mut report = Report::exchanged(id, server, &response, &decoded);
            if let Some(expect) = &job.expect {
                report.failures = expect.check(&decoded.message);
            }
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
            ClientError::Exchange(Failure::TimedOut { .. })
            | ClientError::Tcp(TcpError::TimedOut | TcpError::Closed),
        ) => true,
        Some(ClientError::Udp(e) | ClientError::Tcp(TcpError::Connect(e))) => refused(e),
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
        _ if cli.trace => Route::Trace,
        servers if servers.is_empty() => {
            Route::Servers(vec![server(None, conf.as_ref(), cli.port)?])
        }
        servers => Route::Servers(servers),
    };
    let job = |names: Vec<Name<'static>>, qtype| Job {
        id: Id::of(&names[0], qtype),
        names,
        qtype,
        qclass,
        route: route.clone(),
        options: cli.options,
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
            let options = cli.options.or(query.options).or(file.options);
            options.check().with_context(|| format!("{id}"))?;
            let named = query.server.as_deref().or(file.server.as_deref());
            Ok(Job {
                route: Route::Servers(match &servers {
                    servers if servers.is_empty() => vec![server(named, conf.as_ref(), cli.port)?],
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

/// The addresses of the servers of the command line, in order.
fn servers(cli: &Cli, conf: Option<&ResolvConf>) -> anyhow::Result<Vec<SocketAddr>> {
    cli.servers()
        .iter()
        .map(|named| server(Some(named), conf, cli.port))
        .collect()
}

/// The address of `named`, else of the first name server of `conf`: an address, IPv6 possibly in brackets or
/// with its zone, or a host name, each with or without a port, `port` when without.
fn server(named: Option<&str>, conf: Option<&ResolvConf>, port: u16) -> anyhow::Result<SocketAddr> {
    let text = match named {
        Some(text) => text,
        None => conf
            .and_then(|conf| conf.nameservers.first())
            .ok_or_else(|| {
                anyhow!("no server: give @server, or a nameserver in /etc/resolv.conf")
            })?,
    };
    let bare = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(text);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addresses = match text.to_socket_addrs() {
        Ok(addresses) => addresses,
        Err(_) => (bare, port)
            .to_socket_addrs()
            .with_context(|| format!("server {text}"))?,
    };
    addresses
        .next()
        .ok_or_else(|| anyhow!("server {text}: no address"))
}
