//! A run: the queries of the command line or of a query file, asked concurrently on one compio runtime, their
//! responses printed in the order of the queries (D32), and the exit code (D33).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use anyhow::{Context, anyhow, bail};
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::Failure;
use dedens_net::resolv_conf::ResolvConf;
use dedens_proto::{Class, Message, Name, Question, Rcode, RecordType};
use dedens_scenario::{Expect, Format, Options, QueryFile, Report, default_id};

use crate::args::{Cli, FileFormat};
use crate::idn;
use crate::output::{self, Layout};

/// One query to ask.
struct Job {
    /// The file's id; else the name asked and the type.
    id: Option<String>,
    /// The names to try in order, the next one after an NXDOMAIN (`+search`); never empty.
    names: Vec<Name<'static>>,
    qtype: RecordType,
    qclass: Class,
    server: SocketAddr,
    options: Options,
    expect: Option<Expect>,
}

impl Job {
    fn id(&self, name: &Name<'_>) -> String {
        self.id
            .clone()
            .unwrap_or_else(|| default_id(name, self.qtype))
    }
}

/// Runs `cli`; an error is one of the run as a whole, before any query.
pub(crate) fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    let jobs = match &cli.file {
        Some(path) => file_jobs(cli, path)?,
        None => command_line_jobs(cli)?,
    };
    if let Some(dir) = &cli.save_wire {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let runtime = compio::runtime::Runtime::new().context("cannot start the runtime")?;
    let done = runtime.block_on(async {
        let client = Rc::new(Client::new());
        let handles: Vec<_> = jobs
            .into_iter()
            .map(|job| {
                let client = Rc::clone(&client);
                compio::runtime::spawn(async move {
                    let outcome = ask(&client, &job).await;
                    (job, outcome)
                })
            })
            .collect();
        let mut done = Vec::with_capacity(handles.len());
        for handle in handles {
            done.push(handle.await.map_err(io::Error::from)?);
        }
        io::Result::Ok(done)
    })?;
    let layout = match &cli.output {
        o if o.json => Layout::Json,
        o if o.dig => Layout::Dig,
        o if o.short => Layout::Short,
        _ => Layout::Compact,
    };
    let color = match cli.output.color {
        clap::ColorChoice::Auto => anstream::ColorChoice::Auto,
        clap::ColorChoice::Always => anstream::ColorChoice::Always,
        clap::ColorChoice::Never => anstream::ColorChoice::Never,
    };
    let mut out = anstream::AutoStream::new(io::stdout().lock(), color);
    let mut code = 0;
    for (index, (job, outcome)) in done.iter().enumerate() {
        let (report, wire) = match outcome {
            Ok(answered) => answered,
            Err(error) => {
                eprintln!("dedens: {}: {error:#}", job.id(&job.names[0]));
                code = code.max(if no_reply(error) { 9 } else { 10 });
                continue;
            }
        };
        if index > 0 && layout == Layout::Compact {
            writeln!(out)?;
        }
        output::print(&mut out, layout, report)?;
        if let Some(dir) = &cli.save_wire {
            let path = dir.join(format!("{}.bin", report.id));
            std::fs::write(&path, wire)
                .with_context(|| format!("cannot write {}", path.display()))?;
        }
        for failure in &report.failures {
            eprintln!("dedens: {}: {failure}", report.id);
            code = code.max(1);
        }
    }
    out.flush()?;
    Ok(ExitCode::from(code))
}

/// Asks `job`, trying its names in turn while the response is NXDOMAIN.
async fn ask(client: &Client, job: &Job) -> anyhow::Result<(Report, Vec<u8>)> {
    let options = job.options.exchange();
    let mut names = job.names.iter().peekable();
    while let Some(name) = names.next() {
        let question = Question {
            name: name.clone(),
            qtype: job.qtype,
            qclass: job.qclass,
        };
        let response = client
            .exchange(&job.options.query(question), job.server, &options)
            .await?;
        let message = Message::decode(&response.wire)?.message;
        if names.peek().is_none() || message.rcode() != Rcode::NXDOMAIN {
            let mut report = Report::exchanged(job.id(name), job.server, &response, &message);
            if let Some(expect) = &job.expect {
                report.failures = expect.check(&message);
            }
            return Ok((report, response.wire));
        }
    }
    Err(anyhow!("no name to ask"))
}

/// Whether `error` is the server's silence or refusal of the connection: dig's exit code 9.
fn no_reply(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref(),
        Some(
            ClientError::Exchange(Failure::TimedOut { .. })
                | ClientError::Udp(_)
                | ClientError::Tcp(_)
        )
    )
}

/// The queries of the command line: each name asked the types written after it, up to the next name, as dig
/// reads them; a name without any the types written before the first name, else A. `-x` addresses ask PTR.
fn command_line_jobs(cli: &Cli) -> anyhow::Result<Vec<Job>> {
    // The types before the first name, then each name with the types after it.
    let (mut leading, mut names, mut class) =
        (Vec::new(), Vec::<(&str, Vec<RecordType>)>::new(), Class::IN);
    for word in &cli.words {
        match (word.parse(), word.parse()) {
            (Ok(qtype), _) => names
                .last_mut()
                .map_or(&mut leading, |(_, types)| types)
                .push(qtype),
            (_, Ok(qclass)) => class = qclass,
            _ => names.push((word.as_str(), Vec::new())),
        }
    }
    if names.is_empty() && cli.reverse.is_empty() {
        // dig without a name asks the root its servers.
        names.push((".", Vec::new()));
        if leading.is_empty() {
            leading.push(RecordType::NS);
        }
    }
    if leading.is_empty() {
        leading.push(RecordType::A);
    }
    let conf = (cli.search || cli.server.is_none())
        .then(resolv_conf)
        .transpose()?;
    let server = server(cli.server.as_deref(), conf.as_ref())?;
    let options = Options::from(&cli.options);
    let job = |names, qtype| Job {
        id: None,
        names,
        qtype,
        qclass: class,
        server,
        options,
        expect: None,
    };
    let mut jobs = Vec::new();
    for (text, types) in names {
        let types = if types.is_empty() { &leading } else { &types };
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
        jobs.extend(types.iter().map(|&qtype| job(candidates.clone(), qtype)));
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
    let format = match cli.format {
        Some(FileFormat::Json) => Format::Json,
        Some(FileFormat::Yaml) => Format::Yaml,
        None => Format::of(path).unwrap_or(Format::Yaml),
    };
    let file = QueryFile::parse(&text, format).with_context(|| format!("{}", path.display()))?;
    if let Some(id) = cli
        .only
        .iter()
        .find(|id| !file.queries.iter().any(|q| q.id() == **id))
    {
        bail!("{}: no query with id {id}", path.display());
    }
    let missing = file.server.is_none() && file.queries.iter().any(|q| q.server.is_none());
    let conf = (cli.server.is_none() && missing)
        .then(resolv_conf)
        .transpose()?;
    let options = Options::from(&cli.options).or(Options::default());
    file.queries
        .into_iter()
        .filter(|q| cli.only.is_empty() || cli.only.contains(&q.id()))
        .map(|query| {
            let named = cli
                .server
                .as_deref()
                .or(query.server.as_deref())
                .or(file.server.as_deref());
            Ok(Job {
                id: Some(query.id()),
                server: server(named, conf.as_ref())?,
                names: vec![query.name],
                qtype: query.qtype,
                qclass: Class::IN,
                options: options.or(query.options).or(file.options),
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

/// The address of `named`, an address with or without a port or a host name; else the first name server of
/// `conf`. Port 53 unless given.
fn server(named: Option<&str>, conf: Option<&ResolvConf>) -> anyhow::Result<SocketAddr> {
    let Some(text) = named else {
        let ip = conf
            .and_then(|conf| conf.nameservers.first())
            .ok_or_else(|| {
                anyhow!("no server: give @server, or a nameserver in /etc/resolv.conf")
            })?;
        return Ok(SocketAddr::new(*ip, 53));
    };
    if let Ok(ip) = text.parse() {
        return Ok(SocketAddr::new(ip, 53));
    }
    let mut addresses = match text.to_socket_addrs() {
        Ok(addresses) => addresses,
        Err(_) => (text, 53)
            .to_socket_addrs()
            .with_context(|| format!("server {text}"))?,
    };
    addresses
        .next()
        .ok_or_else(|| anyhow!("server {text}: no address"))
}
