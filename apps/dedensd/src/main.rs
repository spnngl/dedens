//! `dedensd`: a DNS server, a caching forwarder for now (D41-D44).
//!
//! Listens on each address of its configuration file over UDP and TCP, and runs each query through the stages it
//! lists. On Linux, one thread per core, each with its own sockets on the same addresses (`SO_REUSEPORT`) and the
//! kernel spreading queries across them; elsewhere, one thread.

#![forbid(unsafe_code)]

mod config;
mod download;
mod reload;
mod serve;

use std::io::{self, IsTerminal, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;

use anyhow::Context;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use dedens_server::Pipeline;

use crate::config::Config;
use crate::reload::{Current, Fixed};

/// A DNS server: answers from its cache and forwards the rest to upstream servers.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// The configuration file, YAML (D24).
    #[arg(long, short, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Debug events with -v, trace events with -vv.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    /// How events are written on stderr: one JSON object a line, or text for people.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Json)]
    log_format: LogFormat,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Reads the configuration and builds the pipeline, without binding any socket.
    Validate,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    diagnostics(args.verbose, args.log_format);
    // Global, for `dedensd validate --config FILE`, so clap cannot require it.
    let Some(file) = args.config else {
        Args::command()
            .error(
                ErrorKind::MissingRequiredArgument,
                "--config <FILE> is required",
            )
            .exit()
    };
    let path = file.display();
    let text = read(&file)?;
    let config = build(&file, &text, &Pipeline::default())?;
    if let Some(Command::Validate) = args.command {
        writeln!(io::stdout(), "{path}: valid")?;
        return Ok(());
    }
    let current = Arc::new(Current::new(config.pipeline));
    // Every socket is bound before any thread starts, so a taken address fails the start.
    let sockets = (0..threads())
        .map(|_| serve::bind(&config.listen))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let listen = config.listen.clone();
    let presented = config.presented.map(Arc::new);
    // Before "serving" is logged: a SIGHUP from then on reloads, never ends the process (D55).
    reload::control(
        file.clone(),
        text,
        Arc::clone(&current),
        Fixed {
            listen: config.listen,
            trust: config.trust.clone(),
            presented: presented.clone(),
        },
        config.downloads,
    )
    .context("cannot handle SIGHUP")?;
    #[cfg(feature = "doc")]
    for listen in listen
        .iter()
        .filter(|l| matches!(l, config::Listen::Coap(..)))
    {
        tracing::warn!(
            ?listen,
            "CoAP is unprotected, NOT RECOMMENDED (RFC 9953 §6)"
        );
    }
    tracing::info!(config = %path, ?listen, threads = sockets.len(), "serving");
    let (ended, end) = mpsc::channel();
    for sockets in sockets {
        let (current, ended) = (Arc::clone(&current), ended.clone());
        let (trust, presented) = (config.trust.clone(), presented.clone());
        thread::spawn(move || {
            let served = panic::catch_unwind(AssertUnwindSafe(|| {
                let serving = serve::serve(sockets, current, trust, presented);
                serve::runtime().and_then(|runtime| runtime.block_on(serving))
            }));
            let _ =
                ended.send(served.unwrap_or_else(|_| Err(io::Error::other("a thread panicked"))));
        });
    }
    drop(ended);
    // Threads serve until one fails to start or panics; each sends before ending.
    end.recv()?.context("cannot serve")
}

/// The text of the configuration file `file`.
///
/// # Errors
///
/// A file that does not read.
fn read(file: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))
}

/// The configuration `text`, read from `file`, its cache stage that of `previous` while its settings are the same.
///
/// # Errors
///
/// A configuration [`config::read`] refuses.
fn build(file: &Path, text: &str, previous: &Pipeline) -> anyhow::Result<Config> {
    config::read(text, |name| std::env::var(name).ok(), previous)
        .with_context(|| format!("in {}", file.display()))
}

/// The serving threads: one per core on Linux, where `SO_REUSEPORT` spreads queries across their sockets; one
/// elsewhere, where it does not.
fn threads() -> usize {
    if cfg!(target_os = "linux") {
        thread::available_parallelism().map_or(1, usize::from)
    } else {
        1
    }
}

/// Prints `tracing` events on stderr, in `format`: info, debug with `-v`, trace with `-vv` (D30).
fn diagnostics(verbose: u8, format: LogFormat) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    let events = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr);
    match format {
        LogFormat::Json => events.json().init(),
        LogFormat::Text => events
            .with_ansi(io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none())
            .init(),
    }
}
