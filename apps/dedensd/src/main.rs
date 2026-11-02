//! `dedensd`: a DNS server, a caching forwarder for now (D41-D44).
//!
//! Listens on each address of its configuration file over UDP and TCP, and runs each query through the stages it
//! lists. On Linux, `threads` threads, one per core by default, each with its own sockets on the same addresses
//! (`SO_REUSEPORT`) and the kernel spreading queries across them; elsewhere, one thread (D42, D115).

#![forbid(unsafe_code)]

mod config;
mod download;
mod flights;
mod h3_budget;
#[cfg(feature = "odoh")]
mod odoh;
mod reload;
mod serve;

use std::io::{self, IsTerminal, Write};
use std::mem::ManuallyDrop;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;

use anyhow::Context;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use compio::driver::DriverType;
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
    // The key is read here, once: `validate` checks it reads.
    #[cfg(feature = "odoh")]
    let odoh = config
        .odoh
        .as_ref()
        .map(odoh::Section::target)
        .transpose()?
        .map(Arc::new);
    if let Some(Command::Validate) = args.command {
        writeln!(io::stdout(), "{path}: valid")?;
        return Ok(());
    }
    config.warn_access(&config.listen);
    let current = Arc::new(Current::new(config.pipeline));
    // Every socket is bound before any thread starts, so a taken address fails the start.
    let sockets = (0..config.threads)
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
            threads: config.threads,
            trust: config.trust.clone(),
            presented: presented.clone(),
            #[cfg(feature = "odoh")]
            odoh: config.odoh.clone(),
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
    let threads = sockets.len();
    let (ended, end) = mpsc::channel();
    let (listening, listened) = mpsc::channel();
    for sockets in sockets {
        let (current, ended) = (Arc::clone(&current), ended.clone());
        let listening = listening.clone();
        let (trust, presented) = (config.trust.clone(), presented.clone());
        #[cfg(feature = "odoh")]
        let odoh = odoh.clone();
        thread::spawn(move || {
            let served = panic::catch_unwind(AssertUnwindSafe(|| {
                let serving = serve::serve(
                    sockets,
                    current,
                    trust,
                    presented,
                    #[cfg(feature = "odoh")]
                    odoh,
                    listening,
                );
                // Never dropped, not even when `serving` panics: dropping a runtime frees what its ring's
                // operations in flight still point to, which the kernel may write after (D107). The process
                // ends once one thread has, and the kernel then closes the ring.
                serve::runtime().and_then(|runtime| ManuallyDrop::new(runtime).block_on(serving))
            }));
            let _ =
                ended.send(served.unwrap_or_else(|_| Err(io::Error::other("a thread panicked"))));
        });
    }
    drop((ended, listening));
    // Announced once every thread has its sockets; a thread that failed to start never sends, and `end` has why.
    // `listened` ends once each thread has sent or failed.
    let drivers: Vec<_> = listened.iter().collect();
    if drivers.len() == threads {
        let driver = Driver::of(&drivers);
        tracing::info!(config = %path, ?listen, threads, driver = driver.name, "serving");
        if let Some(warning) = driver.warning(cfg!(target_os = "linux")) {
            tracing::warn!(driver = driver.name, threads, "{warning}");
        }
    }
    // Threads serve until one fails to start or panics; each sends before ending.
    end.recv()?.context("cannot serve")
}

/// What the threads' runtimes run on, as logged at start (D107).
#[derive(Debug, PartialEq, Eq)]
struct Driver {
    /// `io_uring`, `poll`, `iocp`, or `mixed` when the threads differ, which no ring built with the same flags does.
    name: &'static str,
    /// Threads on `poll`.
    polling: usize,
    threads: usize,
}

impl Driver {
    fn of(drivers: &[DriverType]) -> Self {
        let name = |driver: &DriverType| match driver {
            DriverType::Poll => "poll",
            DriverType::IoUring => "io_uring",
            DriverType::IOCP => "iocp",
        };
        let name = match drivers {
            [first, rest @ ..] if rest.iter().all(|driver| driver == first) => name(first),
            [] => "none",
            _ => "mixed",
        };
        Self {
            name,
            polling: drivers
                .iter()
                .filter(|driver| **driver == DriverType::Poll)
                .count(),
            threads: drivers.len(),
        }
    }

    /// Why a Linux server on `poll` is a loss: compio falls back from `io_uring` without anyone seeing when the
    /// ring cannot be made, before Linux 5.19 (`COOP_TASKRUN`, D51), under a seccomp filter, or with
    /// `kernel.io_uring_disabled` set; 5.19 is the floor, with no retry without those flags (D107).
    fn warning(&self, linux: bool) -> Option<String> {
        if !linux || self.polling == 0 {
            return None;
        }
        let Self {
            polling, threads, ..
        } = self;
        Some(format!(
            "{polling} of {threads} threads serve on poll, not io_uring, which is slower: io_uring needs Linux 5.19 or later, and no seccomp filter or `kernel.io_uring_disabled` refusing it"
        ))
    }
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

#[cfg(test)]
mod tests {
    use compio::driver::DriverType::{IoUring, Poll};

    use super::Driver;

    /// D107: a Linux server on `poll` warns, a server on `io_uring` or elsewhere does not; the threads' drivers are
    /// one name, `mixed` when they differ.
    #[test]
    fn poll_on_linux_warns() {
        let uring = Driver::of(&[IoUring, IoUring]);
        assert_eq!((uring.name, uring.warning(true)), ("io_uring", None));
        let poll = Driver::of(&[Poll, Poll]);
        assert_eq!(poll.name, "poll");
        assert_eq!(poll.warning(false), None);
        let warning = poll.warning(true).expect("a warning");
        assert!(
            warning.starts_with("2 of 2 threads serve on poll"),
            "{warning}"
        );
        let mixed = Driver::of(&[IoUring, Poll, IoUring]);
        assert_eq!(mixed.name, "mixed");
        let warning = mixed.warning(true).expect("a warning");
        assert!(
            warning.starts_with("1 of 3 threads serve on poll"),
            "{warning}"
        );
    }
}
