//! `dedensd`: a DNS server, a caching forwarder for now (D41-D44).
//!
//! Listens on each address of its configuration file over UDP and TCP, and runs each query through the stages it
//! lists. On Linux, `threads` threads, one per core by default, each with its own sockets on the same addresses
//! (`SO_REUSEPORT`) and the kernel spreading queries across them; elsewhere, one thread (D42, D115).

#![forbid(unsafe_code)]

// D154: on musl, mimalloc in its secure mode replaces musl's allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod config;
mod download;
mod flights;
mod lists;
mod log;
#[cfg(feature = "odoh")]
mod odoh;
mod privileges;
mod reload;
mod serve;
mod sync;

use std::io::{self, Write};
use std::mem::ManuallyDrop;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;

use anyhow::Context;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand};
use dedens_server::Pipeline;

use crate::config::Config;
use crate::lists::Store;
use crate::log::{LogFormat, announce, diagnostics};
use crate::reload::{Current, Fixed};
use crate::serve::isolate;

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
        .map(odoh::Section::service)
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
    log::warn_coap(&listen);
    let threads = sockets.len();
    let (ended, end) = stop_on_signal().context("cannot handle SIGTERM")?;
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

/// Ends the server on SIGTERM or SIGINT (D157), as `docker stop`, systemd and Ctrl-C ask: at once, since nothing is
/// to flush (the cache lives in memory, a list and its `ETag` are replaced atomically, D64). Needed as PID 1 of the
/// image, where the kernel drops a signal that has no handler. The thread starts after root is dropped (D122).
///
/// The channel the server's end comes on: from a serving thread, or from the signal.
///
/// # Errors
///
/// A handler the OS refuses.
fn stop_on_signal() -> io::Result<Ending> {
    let (ended, end) = mpsc::channel();
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};
        let mut signals = signal_hook::iterator::Signals::new([SIGTERM, SIGINT])?;
        let ended = ended.clone();
        thread::Builder::new()
            .name("dedensd-signals".to_owned())
            .spawn(move || {
                if let Some(signal) = signals.forever().next() {
                    let signal = if signal == SIGTERM {
                        "SIGTERM"
                    } else {
                        "SIGINT"
                    };
                    tracing::info!(signal, "dedensd ends: stopped");
                    let _ = ended.send(Ok(()));
                }
            })?;
    }
    Ok((ended, end))
}

/// The two ends of [`stop_on_signal`]'s channel.
type Ending = (mpsc::Sender<io::Result<()>>, mpsc::Receiver<io::Result<()>>);

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
    privileges::apply(plan, downloads.written_dir())?;
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

#[cfg(test)]
mod tests {
    /// D158: the packaged man page is this command line's, section 8, without the version, which the package has;
    /// `just man` writes it again.
    #[test]
    fn the_man_page_is_the_command_lines() {
        use clap::CommandFactory as _;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/packages/man/dedensd.8"
        );
        let mut page = Vec::new();
        clap_mangen::Man::new(super::Args::command().version(None::<&str>))
            .section("8")
            .render(&mut page)
            .expect("rendered");
        if std::env::var_os("DEDENS_WRITE_MAN").is_some() {
            std::fs::write(path, &page).expect("written");
        }
        let committed = std::fs::read(path).unwrap_or_default();
        assert!(
            committed == page,
            "{path} is stale: `just man` writes it again"
        );
    }
}
