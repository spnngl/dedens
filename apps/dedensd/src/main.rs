//! `dedensd`: a DNS server, a caching forwarder for now (D41-D44).
//!
//! Listens on each address of its configuration file over UDP and TCP, and runs each query through the stages it
//! lists. On Linux, one thread per core, each with its own sockets on the same addresses (`SO_REUSEPORT`) and the
//! kernel spreading queries across them; elsewhere, one thread.

#![forbid(unsafe_code)]

mod config;
mod serve;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;

use anyhow::Context;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand};

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
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Reads the configuration and builds the pipeline, without binding any socket.
    Validate,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    diagnostics(args.verbose);
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
    let text = std::fs::read_to_string(&file).with_context(|| format!("cannot read {path}"))?;
    let config = config::read(&text, |name| std::env::var(name).ok())
        .with_context(|| format!("in {path}"))?;
    if let Some(Command::Validate) = args.command {
        writeln!(io::stdout(), "{path}: valid")?;
        return Ok(());
    }
    let pipeline = Arc::new(config.pipeline);
    // Every socket is bound before any thread starts, so a taken address fails the start.
    let sockets = (0..threads())
        .map(|_| serve::bind(&config.listen))
        .collect::<anyhow::Result<Vec<_>>>()?;
    tracing::info!(config = %path, listen = ?config.listen, threads = sockets.len(), "serving");
    let (ended, end) = mpsc::channel();
    for sockets in sockets {
        let (pipeline, ended) = (Arc::clone(&pipeline), ended.clone());
        thread::spawn(move || {
            let served = compio::runtime::Runtime::new()
                .and_then(|runtime| runtime.block_on(serve::serve(sockets, pipeline)));
            let _ = ended.send(served);
        });
    }
    // Threads serve until one fails to start.
    match end.recv() {
        Ok(served) => served.context("cannot serve"),
        Err(mpsc::RecvError) => Ok(()),
    }
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

/// Prints `tracing` events on stderr, as text: info, debug with `-v`, trace with `-vv` (D30).
fn diagnostics(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none())
        .init();
}
