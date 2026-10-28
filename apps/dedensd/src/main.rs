//! `dedensd`: a DNS server, a caching forwarder for now (D41, D42, D43).
//!
//! Listens on each `--listen` address over UDP and TCP, answers from its cache, and forwards the rest to the
//! `--upstream` servers in order. On Linux,
//! one thread per core, each with its own sockets on the same addresses (`SO_REUSEPORT`) and the kernel spreading
//! queries across them; elsewhere, one thread.

#![forbid(unsafe_code)]

mod serve;

use std::io::{self, IsTerminal};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, mpsc};
use std::thread;

use anyhow::Context;
use clap::Parser;
use dedens_cache::{Cache, Config};
use dedens_server::{Forward, Pipeline, Stage};

/// A DNS server: forwards queries to upstream servers.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Address to answer on, over UDP and TCP; repeat for several.
    #[arg(long, required = true, value_name = "IP:PORT")]
    listen: Vec<SocketAddr>,
    /// Server to forward to, asked in the order given; port 53 unless one is given.
    #[arg(long = "upstream", required = true, value_name = "IP[:PORT]", value_parser = upstream)]
    upstreams: Vec<SocketAddr>,
    /// Debug events with -v, trace events with -vv.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    diagnostics(args.verbose);
    let forward = Forward::new(&args.upstreams).context("no upstream server")?;
    let cache = Cache::new(Config::default()).context("cannot set the cache up")?;
    let pipeline = Arc::new(Pipeline::new(vec![
        Stage::Cache(cache),
        Stage::Forward(forward),
    ]));
    // Every socket is bound before any thread starts, so a taken address fails the start.
    let sockets = (0..threads())
        .map(|_| serve::bind(&args.listen))
        .collect::<anyhow::Result<Vec<_>>>()?;
    tracing::info!(listen = ?args.listen, upstreams = ?args.upstreams, threads = sockets.len(), "serving");
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

/// An upstream server: an address with its port, or an IP address on port 53.
fn upstream(text: &str) -> Result<SocketAddr, String> {
    text.parse()
        .or_else(|_| text.parse().map(|ip: IpAddr| SocketAddr::new(ip, 53)))
        .map_err(|_| format!("`{text}` is neither IP:PORT nor IP"))
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
