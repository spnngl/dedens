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
use dedens_scenario::{Expect, Id, Options, QueryFile, Report};

use crate::args::{self, Cli};
use crate::idn;
use crate::output::{self, Format};

/// The queries in flight at most: each holds a socket.
const IN_FLIGHT: usize = 64;

/// One query to ask.
struct Job {
    id: Id,
    /// The names to try in order, the next one after an NXDOMAIN (`+search`); never empty.
    names: Vec<Name<'static>>,
    qtype: RecordType,
    qclass: Class,
    server: SocketAddr,
    options: Options,
    expect: Option<Expect>,
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
    let runtime = compio::runtime::Runtime::new().context("cannot start the runtime")?;
    let code = runtime.block_on(async {
        let client = Rc::new(Client::new());
        let mut jobs = jobs.into_iter();
        let mut running = VecDeque::new();
        let (mut code, mut printed) = (0, false);
        loop {
            let room = IN_FLIGHT - running.len();
            running.extend(jobs.by_ref().take(room).map(|job| {
                let client = Rc::clone(&client);
                let id = job.id.clone();
                (
                    id,
                    compio::runtime::spawn(async move { ask(&client, &job).await }),
                )
            }));
            let Some((id, handle)) = running.pop_front() else {
                break;
            };
            let outcome = handle
                .await
                .map_err(|e| anyhow::Error::from(io::Error::from(e)))
                .and_then(|outcome| outcome);
            code = code.max(show(cli, format, &mut out, &id, outcome, &mut printed)?);
        }
        io::Result::Ok(code)
    })?;
    Ok(ExitCode::from(code))
}

/// Prints the outcome of query `id` and saves its response; returns the exit code it calls for. `printed` tells
/// whether a report came before, which the human format sets apart.
fn show(
    cli: &Cli,
    format: Format,
    out: &mut impl Write,
    id: &Id,
    outcome: anyhow::Result<(Report, Vec<u8>)>,
    printed: &mut bool,
) -> io::Result<u8> {
    let (report, wire) = match outcome {
        Ok(answered) => answered,
        Err(error) => {
            eprintln!("dedens: {id}: {error:#}");
            return Ok(if no_reply(&error) { 9 } else { 10 });
        }
    };
    if std::mem::replace(printed, true) && format == Format::Human {
        writeln!(out)?;
    }
    output::print(out, format, &report)?;
    out.flush()?;
    if format == Format::Short {
        for line in report.violations.iter().chain(&report.failures) {
            eprintln!("dedens: {id}: {line}");
        }
    }
    let mut code = u8::from(!report.failures.is_empty());
    if let Some(dir) = &cli.save_wire {
        let path = dir.join(format!("{id}.bin"));
        if let Err(error) = std::fs::write(&path, wire) {
            eprintln!("dedens: cannot write {}: {error}", path.display());
            code = 10;
        }
    }
    Ok(code)
}

/// Asks `job`, trying its names in turn while the response is NXDOMAIN.
async fn ask(client: &Client, job: &Job) -> anyhow::Result<(Report, Vec<u8>)> {
    let options = job.options.exchange();
    for (index, name) in job.names.iter().enumerate() {
        let question = Question {
            name: name.clone(),
            qtype: job.qtype,
            qclass: job.qclass,
        };
        let response = client
            .exchange(&job.options.query(question), job.server, &options)
            .await?;
        let decoded = Message::decode(&response.wire)?;
        if index + 1 == job.names.len() || decoded.message.rcode() != Rcode::NXDOMAIN {
            let mut report = Report::exchanged(job.id.clone(), job.server, &response, &decoded);
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
    let conf = (cli.search || cli.server().is_none())
        .then(resolv_conf)
        .transpose()?;
    let server = server(cli.server(), conf.as_ref(), cli.port)?;
    let job = |names: Vec<Name<'static>>, qtype| Job {
        id: Id::of(&names[0], qtype),
        names,
        qtype,
        qclass,
        server,
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
    let conf = (cli.server().is_none() && missing)
        .then(resolv_conf)
        .transpose()?;
    file.queries
        .into_iter()
        .filter(|q| cli.only.is_empty() || cli.only.contains(&q.id()))
        .map(|query| {
            let id = query.id();
            let options = cli.options.or(query.options).or(file.options);
            options.check().with_context(|| format!("{id}"))?;
            let named = cli
                .server()
                .or(query.server.as_deref())
                .or(file.server.as_deref());
            Ok(Job {
                server: server(named, conf.as_ref(), cli.port)?,
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
