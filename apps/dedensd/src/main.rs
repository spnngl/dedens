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
mod isolate;
mod lists;
#[cfg(feature = "odoh")]
mod odoh;
mod privileges;
mod reload;
mod serve;
mod sync;

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
use crate::lists::Store;
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
    let mut store = Store::default();
    let config = build(&file, &text, &Pipeline::default(), &mut store)?;
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
    // Resolved while still root, so a user or a group that does not exist fails the start before any socket is bound.
    let plan = privileges::resolve(config.user.as_ref()).with_context(|| format!("in {path}"))?;
    config.warn_access(&config.listen);
    isolate::describe();
    isolate::hook();
    // Every socket is bound before any thread starts, so a taken address fails the start.
    let sockets = (0..config.threads)
        .map(|_| serve::bind(&config.listen))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let listen = config.listen.clone();
    let presented = config.presented.map(Arc::new);
    // Everything that needs root is done: the sockets are bound, and the keys and lists of the start are read. Nothing
    // has started a thread yet, so none keeps root; a reload reads as the user (D122).
    let (text, store, pipeline, downloads) = match drop_root(plan, &config.downloads, &file)? {
        Some((text, store, again)) => (text, store, again.pipeline, again.downloads),
        None => (text, store, config.pipeline, config.downloads),
    };
    let current = Arc::new(Current::new(pipeline));
    // Before "serving" is logged: a SIGHUP from then on reloads, never ends the process (D55).
    reload::control(
        file.clone(),
        text,
        Arc::clone(&current),
        Fixed {
            listen: config.listen,
            threads: config.threads,
            user: config.user,
            trust: config.trust.clone(),
            presented: presented.clone(),
            #[cfg(feature = "odoh")]
            odoh: config.odoh.clone(),
        },
        downloads,
        store,
    )
    .context("cannot handle SIGHUP")?;
    #[cfg(feature = "doc")]
    warn_coap(&listen);
    let threads = sockets.len();
    let (ended, end) = mpsc::channel();
    let (listening, listened) = mpsc::channel();
    for (index, sockets) in sockets.into_iter().enumerate() {
        let (current, ended) = (Arc::clone(&current), ended.clone());
        let listening = listening.clone();
        let (trust, presented) = (config.trust.clone(), presented.clone());
        #[cfg(feature = "odoh")]
        let odoh = odoh.clone();
        let serving = move || {
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
            // A panic here is the runtime's, or a driver's: tasks and listeners catch their own (D121).
            let _ = ended.send(served.unwrap_or_else(|payload| Err(isolate::fatal(&*payload))));
        };
        thread::Builder::new()
            .name(format!("dedensd-{index}"))
            .spawn(serving)
            .context("cannot start a thread")?;
    }
    drop((ended, listening));
    // Announced once every thread has its sockets; a thread that failed to start never sends, and `end` has why.
    // `listened` ends once each thread has sent or failed.
    let drivers: Vec<_> = listened.iter().collect();
    if drivers.len() == threads {
        announce(&path.to_string(), &listen, &drivers);
    }
    // Threads serve until one fails to start or panics; each sends before ending.
    match end.recv()? {
        Ok(()) => Ok(()),
        // Logged as the rest of what the server says, not only printed: its log is where it is looked for (D121).
        Err(error) => {
            tracing::error!(error = format!("{error:#}"), "dedensd ends: cannot serve");
            std::process::exit(1)
        }
    }
}

/// Warns of each CoAP address in `listen`: DNS there is unprotected (RFC 9953 §6).
#[cfg(feature = "doc")]
fn warn_coap(listen: &[config::Listen]) {
    for listen in listen
        .iter()
        .filter(|l| matches!(l, config::Listen::Coap(..)))
    {
        tracing::warn!(
            ?listen,
            "CoAP is unprotected, NOT RECOMMENDED (RFC 9953 §6)"
        );
    }
}

/// Logs that the server is serving `listen`, on the `drivers` of its threads, and warns of a driver that is a loss.
fn announce(config: &str, listen: &[config::Listen], drivers: &[DriverType]) {
    let (driver, threads) = (Driver::of(drivers), drivers.len());
    tracing::info!(config, ?listen, threads, driver = driver.name, "serving");
    if let Some(warning) = driver.warning(cfg!(target_os = "linux")) {
        tracing::warn!(driver = driver.name, threads, "{warning}");
    }
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

/// Applies `plan` (D122). After a drop, the configuration `file` is read again as the user, so that a file it cannot
/// read fails the start, not the first reload: its text, the store of its lists, and what it says.
///
/// # Errors
///
/// [`privileges::apply`] failing; after a drop, a file the user cannot read, or a configuration [`build`] refuses with
/// the files it names read as the user.
fn drop_root(
    plan: privileges::Plan,
    downloads: &config::Downloads,
    file: &Path,
) -> anyhow::Result<Option<(String, Store, Config)>> {
    let dropping = matches!(plan, privileges::Plan::Drop { .. });
    privileges::apply(
        plan,
        (!downloads.urls.is_empty()).then_some(downloads.dir.as_path()),
    )?;
    if !dropping {
        return Ok(None);
    }
    let again = || -> anyhow::Result<_> {
        let text = read(file)?;
        let mut store = Store::default();
        let config = build(file, &text, &Pipeline::default(), &mut store)?;
        Ok((text, store, config))
    };
    again()
        .map(Some)
        .context("after dropping to `user`, the configuration or a file it names cannot be read: make them readable by it (D122)")
}

/// The configuration `text`, read from `file`, its cache stage that of `previous` while its settings are the same.
///
/// # Errors
///
/// A configuration [`config::read`] refuses.
fn build(
    file: &Path,
    text: &str,
    previous: &Pipeline,
    store: &mut Store,
) -> anyhow::Result<Config> {
    config::read(text, |name| std::env::var(name).ok(), previous, store)
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
