//! `dedensd`: a DNS server, a caching forwarder for now (D41-D44), a library the binary and `fuzz/` reach (D181):
//! [`main`] runs the server, [`read_config`] only reads a configuration; `simulated`, hidden, runs the serving loop
//! of UDP and TCP on `dedens-sim`'s turmoil (D182).
//!
//! Listens on each address of its configuration file over UDP and TCP, and runs each query through the stages it
//! lists. On Linux, `threads` threads, one per core by default, each with its own sockets on the same addresses
//! (`SO_REUSEPORT`) and the kernel spreading queries across them; elsewhere, one thread (D42, D115).

#![forbid(unsafe_code)]

mod config;
#[cfg(feature = "dnscrypt")]
mod dnscrypt;
mod download;
mod flights;
mod lists;
mod log;
#[cfg(feature = "odoh")]
mod odoh;
mod privileges;
mod reload;
mod rollover;
mod roots;
mod secondary;
mod serve;
mod sync;
mod zones;

use std::io::{self, Write};
use std::mem::ManuallyDrop;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand};
use dedens_server::Pipeline;

use crate::config::Config;
use crate::lists::Store;
use crate::log::{LogFormat, announce, diagnostics};
use crate::reload::{Current, Fixed};
use crate::serve::{Services, isolate};

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
    /// Makes the provider key of a `DNSCrypt` resolver (D99): prints the `secret_key` line for the `dnscrypt` section of
    /// the configuration, and the stamp clients use. Needs the dnscrypt feature.
    DnscryptKeygen {
        /// The provider name, starting with `2.dnscrypt-cert.`.
        #[arg(long, value_name = "NAME")]
        provider_name: String,
        /// The address clients reach the resolver at, IP or IP:PORT, port 443 by default.
        #[arg(long, value_name = "ADDR")]
        address: String,
    },
}

/// Runs `dedensd` on the process's command line, until a signal ends it or a serving thread fails.
///
/// # Errors
///
/// A configuration that does not read, a socket that does not bind, root that cannot be dropped, a signal that cannot
/// be handled, a thread that does not start.
pub fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    diagnostics(args.verbose, args.log_format);
    if let Some(Command::DnscryptKeygen {
        provider_name,
        address,
    }) = &args.command
    {
        return keygen(provider_name, address);
    }
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
    let mut text = read(&file)?;
    let mut store = Store::default();
    let mut config = build(&file, &text, (&Pipeline::default(), None), &mut store)?;
    // The keys are read here, once: `validate` checks they read.
    let services = Services::new(&config)?;
    if let Some(Command::Validate) = args.command {
        writeln!(io::stdout(), "{path}: valid")?;
        return Ok(());
    }
    // Resolved while still root, so a user or a group that does not exist fails the start before any socket is bound.
    let plan = privileges::resolve(config.user.as_ref()).with_context(|| format!("in {path}"))?;
    config.warn_access(&config.listen);
    process();
    // Every socket is bound before any thread starts, so a taken address fails the start.
    let sockets = (0..config.threads)
        .map(|_| serve::bind(&config.listen))
        .collect::<anyhow::Result<Vec<_>>>()?;
    // Everything that needs root is done: the sockets are bound, and the keys and lists of the start are read. Nothing
    // has started a thread yet, so none keeps root; a reload reads as the user (D122). What was read as root is
    // replaced, not kept beside what serves.
    if let Some((again, read)) = drop_root(plan, &config, &file, &mut store)? {
        (text, config.pipeline, config.downloads, config.secondaries) =
            (again, read.pipeline, read.downloads, read.secondaries);
    }
    let listen = config.listen.clone();
    let presented = config.presented.map(Arc::new);
    let current = Arc::new(Current::new(config.pipeline));
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
            #[cfg(feature = "dnscrypt")]
            dnscrypt: config.dnscrypt.clone(),
        },
        config.downloads,
        (store, config.secondaries),
    )
    .context("cannot handle SIGHUP")?;
    log::notices(&listen, &services);
    let threads = sockets.len();
    let (ends, end) = stop_on_signal().context("cannot handle SIGTERM")?;
    let (listening, listened) = mpsc::channel();
    for (index, sockets) in sockets.into_iter().enumerate() {
        let (current, ends, listening) = (Arc::clone(&current), ends.clone(), listening.clone());
        let (trust, presented) = (config.trust.clone(), presented.clone());
        let services = services.clone();
        let serving = move || {
            let served = panic::catch_unwind(AssertUnwindSafe(|| {
                let serving = serve::serve(
                    sockets,
                    current,
                    trust,
                    presented,
                    services,
                    index == 0,
                    listening,
                    ends.stopping.clone(),
                );
                // Never dropped, not even when `serving` panics: dropping a runtime frees what its ring's
                // operations in flight still point to, which the kernel may write after (D107). The process
                // ends once one thread has, and the kernel then closes the ring.
                serve::runtime().and_then(|runtime| ManuallyDrop::new(runtime).block_on(serving))
            }));
            // A panic here is the runtime's, or a driver's: tasks and listeners catch their own (D121).
            ends.served(served.unwrap_or_else(|payload| Err(isolate::fatal(&*payload))));
        };
        thread::Builder::new()
            .name(format!("dedensd-{index}"))
            .spawn(serving)
            .context("cannot start a thread")?;
    }
    drop((ends, listening));
    // Announced once every thread has its sockets; a thread that failed to start never sends, and `end` has why.
    // `listened` ends once each thread has sent or failed.
    let drivers: Vec<_> = listened.iter().collect();
    if drivers.len() == threads {
        announce(&path.to_string(), &listen, &drivers);
    }
    // Threads serve until one fails to start or panics, which it sends, or until the signal's thread sends the stop.
    match end.recv()? {
        Ok(()) => Ok(()),
        // Logged as the rest of what the server says, not only printed: its log is where it is looked for (D121).
        Err(error) => {
            tracing::error!(error = format!("{error:#}"), "dedensd ends: cannot serve");
            std::process::exit(1)
        }
    }
}

/// Reads `text` as [`main`] reads its configuration file, `${VAR}` taken from `env`, and builds what it says unless it
/// names a file to read: the entry of `fuzz/` (D181), which must not open the paths an input names.
///
/// # Errors
///
/// A configuration [`main`] refuses.
pub fn read_config(text: &str, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
    config::read_without_files(text, env)
}

/// Answers over UDP on `udp` and TCP on `tcp`, both bound before, with `pipeline`, on the runtime `io`, upstream
/// servers over TLS checked against `trust`: [`main`]'s serving loop of a plain listener, supervised, for the
/// simulation tests (D182). Not an API: what it takes follows the loop. Never ends.
#[doc(hidden)]
pub async fn simulated<N: dedens_net::io::Io>(
    io: N,
    udp: N::Udp,
    tcp: N::Listener,
    pipeline: Pipeline,
    trust: dedens_net::tls::Trust,
) {
    serve::simulated(io, udp, tcp, pipeline, trust).await;
}

/// The `DNSCrypt` provider of [`simulated_dnscrypt`]: its `name`, the `seed` it signs with, the Unix time `unix` its
/// first keys are made at.
#[cfg(feature = "dnscrypt")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct SimulatedProvider<'a> {
    pub name: &'a str,
    pub seed: &'a [u8; 32],
    pub unix: u64,
}

/// As [`simulated`], answering `DNSCrypt` as `provider`, both encryption systems offered (D99, D182).
///
/// # Errors
///
/// A provider name or a seed `dedensd` refuses. Otherwise never ends.
#[cfg(feature = "dnscrypt")]
#[doc(hidden)]
pub async fn simulated_dnscrypt<N: dedens_net::io::Io>(
    io: N,
    udp: N::Udp,
    tcp: N::Listener,
    pipeline: Pipeline,
    trust: dedens_net::tls::Trust,
    provider: &SimulatedProvider<'_>,
) -> anyhow::Result<()> {
    use dedens_dnscrypt::EncryptionSystem;

    let SimulatedProvider { name, seed, unix } = *provider;

    let systems = vec![
        EncryptionSystem::XChaCha20Poly1305,
        EncryptionSystem::XSalsa20Poly1305,
        EncryptionSystem::XWing,
    ];
    let service = dnscrypt::Service::new(seed, config::provider(name)?, systems, unix, &io)?;
    serve::simulated_dnscrypt(io, udp, tcp, pipeline, trust, Arc::new(service)).await;
    Ok(())
}

/// The `secret_key` and the stamp of a new `DNSCrypt` provider (`dedensd dnscrypt-keygen`), printed.
///
/// # Errors
///
/// Arguments the command refuses, a build without the `dnscrypt` feature, or output that cannot be written.
fn keygen(provider_name: &str, address: &str) -> anyhow::Result<()> {
    #[cfg(feature = "dnscrypt")]
    {
        let text = dnscrypt::keygen(provider_name, address)?;
        write!(io::stdout(), "{text}")?;
        Ok(())
    }
    #[cfg(not(feature = "dnscrypt"))]
    {
        let _ = (provider_name, address);
        anyhow::bail!("`dnscrypt-keygen` needs a dedensd built with the dnscrypt feature")
    }
}

/// Ends the server on SIGTERM or SIGINT (D157), as `docker stop`, systemd and Ctrl-C ask: once the serving threads
/// have closed their QUIC connections, [`CLOSING`] at most, as nothing else is to flush (the cache lives in memory, a
/// list and its `ETag` are replaced atomically, D64). Needed as PID 1 of the image, where the kernel drops a
/// signal that has no handler. The thread starts after root is dropped (D122).
///
/// # Errors
///
/// A handler the OS refuses.
fn stop_on_signal() -> io::Result<(Ending, mpsc::Receiver<io::Result<()>>)> {
    let (ended, end) = mpsc::channel();
    let (stop, stopping) = flume::bounded(0);
    let (closed, all_closed) = mpsc::channel();
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
                    drop(stop);
                    // Disconnected once each serving thread has closed, as nothing sends on it.
                    let _ = all_closed.recv_timeout(CLOSING);
                    let _ = ended.send(Ok(()));
                }
            })?;
    }
    #[cfg(not(unix))]
    {
        // No signal: the server is never stopped, and `stopping` must not disconnect.
        std::mem::forget(stop);
        drop(all_closed);
    }
    let ending = Ending {
        ended,
        stopping,
        closed,
    };
    Ok((ending, end))
}

/// The most a stopped server waits for its threads to close their QUIC connections (D157).
#[cfg(unix)]
const CLOSING: Duration = Duration::from_secs(1);

/// A serving thread's ends of [`stop_on_signal`]'s channels; the receiver of the server's end is [`main`]'s.
#[derive(Clone)]
struct Ending {
    /// Where the server's end comes: a serving thread's failure, or the signal once the threads have closed.
    ended: mpsc::Sender<io::Result<()>>,
    /// Disconnected by the signal: the serving thread then closes its QUIC connections.
    stopping: flume::Receiver<()>,
    /// Held by the serving thread until it has closed them.
    closed: mpsc::Sender<()>,
}

impl Ending {
    /// The thread's serving ended as `served` says: a failure ends the server; a stop is the signal's, whose thread
    /// ends the server once each serving thread dropped its `Ending`.
    fn served(self, served: io::Result<()>) {
        let Self { ended, closed, .. } = self;
        if let Err(error) = served {
            let _ = ended.send(Err(error));
        }
        drop(closed);
    }
}

/// Sets what the whole process holds to before its threads start: the descriptions of the metrics, the panic hook
/// (D121), and on Unix the limit of open descriptors ([`descriptors`]).
fn process() {
    serve::describe();
    rollover::describe();
    secondary::describe();
    zones::describe();
    isolate::hook();
    #[cfg(unix)]
    descriptors();
}

/// Raises the soft limit of open descriptors to the hard one: a recurse stage opens a socket per query to an
/// authoritative server, up to 1056 a thread (D190), past the 1024 most systems start a process with. Done whatever
/// the pipeline, which a reload may give a recurse stage, as BIND's `named_os_adjustnofile` and Unbound's
/// `checkrlimits` do at start (D195). The limit obtained is logged, or the failure: the queries past the limit wait,
/// then fail.
#[cfg(unix)]
fn descriptors() {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let raised = getrlimit(Resource::RLIMIT_NOFILE).and_then(|(soft, hard)| {
        if soft < hard {
            raise(soft, hard, |soft| {
                setrlimit(Resource::RLIMIT_NOFILE, soft, hard)
            })?;
        }
        getrlimit(Resource::RLIMIT_NOFILE)
    });
    match raised {
        Ok((limit, _)) => tracing::info!(limit, "open descriptors"),
        Err(error) => tracing::warn!(%error, "cannot raise the limit of open descriptors"),
    }
}

/// macOS's `OPEN_MAX` (`sys/syslimits.h`), the soft limit of open descriptors its `setrlimit(2)` asks for when the
/// hard one is refused: it refuses an unlimited soft limit, and one above `kern.maxfilesperproc`, with `EINVAL`.
#[cfg(unix)]
const OPEN_MAX: nix::sys::resource::rlim_t = 10_240;

/// Raises the soft limit of open descriptors from `soft` with `set`: to `hard`, or to [`OPEN_MAX`] at most where
/// `hard` is refused with `EINVAL`, as macOS refuses an unlimited one; never below `soft`, which may be above
/// [`OPEN_MAX`] already.
#[cfg(unix)]
fn raise(
    soft: nix::sys::resource::rlim_t,
    hard: nix::sys::resource::rlim_t,
    set: impl Fn(nix::sys::resource::rlim_t) -> nix::Result<()>,
) -> nix::Result<()> {
    match set(hard) {
        Err(nix::errno::Errno::EINVAL) => set(hard.min(OPEN_MAX).max(soft)),
        set => set,
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
/// read fails the start, not the first reload: its text and what it says. It is read as a reload reads it, after
/// `previous` built with `store`: each file is opened as the user, and parsed again only if it changed since
/// (D120), the caches kept (D55).
///
/// # Errors
///
/// [`privileges::apply`] failing; after a drop, a file the user cannot read, or a configuration [`build`] refuses with
/// the files it names read as the user.
fn drop_root(
    plan: privileges::Plan,
    previous: &Config,
    file: &Path,
    store: &mut Store,
) -> anyhow::Result<Option<(String, Config)>> {
    let dropping = matches!(plan, privileges::Plan::Drop { .. });
    let downloads = &previous.downloads;
    let zones = secondary::dir(&downloads.state_dir);
    let written: Vec<_> = (downloads.written_dir().map(|dir| ("downloads.dir", dir)))
        .into_iter()
        .chain((!previous.secondaries.is_empty()).then_some(("state_dir", zones.as_path())))
        .collect();
    privileges::apply(plan, &written, &downloads.roots_dirs())?;
    if !dropping {
        return Ok(None);
    }
    let mut again = || -> anyhow::Result<_> {
        let text = read(file)?;
        let config = build(
            file,
            &text,
            (&previous.pipeline, Some(previous.threads)),
            store,
        )?;
        Ok((text, config))
    };
    again()
        .map(Some)
        .context("after dropping to `user`, the configuration or a file it names cannot be read: make them readable by it (D122)")
}

/// The configuration `text`, read from `file`, its cache stage that of `previous` while its settings are the same,
/// for a server serving with `started` threads, `None` before it starts.
///
/// # Errors
///
/// A configuration [`config::read`] refuses.
fn build(
    file: &Path,
    text: &str,
    previous: (&Pipeline, Option<usize>),
    store: &mut Store,
) -> anyhow::Result<Config> {
    config::read(text, |name| std::env::var(name).ok(), previous, store)
        .with_context(|| format!("in {}", file.display()))
}

#[cfg(test)]
mod tests {
    /// D195: an unlimited hard limit refused, as macOS refuses it, the soft limit is raised to `OPEN_MAX`, never
    /// lowered to it; a hard limit taken, or refused for another reason, is the end of it.
    #[cfg(unix)]
    #[test]
    fn d195_the_descriptors_are_raised_to_open_max_where_the_hard_limit_is_refused() {
        use std::cell::RefCell;

        use nix::errno::Errno;
        use nix::sys::resource::RLIM_INFINITY;

        use super::{OPEN_MAX, raise};

        // From `soft`, the system refuses with `refused` a soft limit above `OPEN_MAX` and `soft`.
        for (soft, hard, refused, result, tried) in [
            (
                256,
                RLIM_INFINITY,
                Errno::EINVAL,
                Ok(()),
                vec![RLIM_INFINITY, OPEN_MAX],
            ),
            (256, 20_000, Errno::EINVAL, Ok(()), vec![20_000, OPEN_MAX]),
            (256, 4096, Errno::EINVAL, Ok(()), vec![4096]),
            (
                256,
                RLIM_INFINITY,
                Errno::EPERM,
                Err(Errno::EPERM),
                vec![RLIM_INFINITY],
            ),
            // `launchctl limit maxfiles 20000 unlimited`: kept, not lowered to `OPEN_MAX`.
            (
                20_000,
                RLIM_INFINITY,
                Errno::EINVAL,
                Ok(()),
                vec![RLIM_INFINITY, 20_000],
            ),
        ] {
            let set = RefCell::new(Vec::new());
            let got = raise(soft, hard, |to| {
                set.borrow_mut().push(to);
                if to > OPEN_MAX.max(soft) {
                    Err(refused)
                } else {
                    Ok(())
                }
            });
            assert_eq!((got, set.take()), (result, tried), "{hard}");
        }
    }

    /// D195: this process's soft limit is raised to its hard one, or to `OPEN_MAX` at least where the system refuses
    /// that (macOS's unlimited one).
    #[cfg(unix)]
    #[test]
    fn d195_the_descriptors_are_raised() {
        use nix::sys::resource::{Resource, getrlimit};

        super::descriptors();
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("the limit");
        assert!(soft >= hard.min(super::OPEN_MAX), "{soft} of {hard}");
    }

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

    /// D181: the entry of `fuzz/` builds a configuration that names no file, its mistakes found, and only reads one
    /// that names a file: none of these is opened. Each text has no pipeline, a mistake the build finds.
    #[test]
    fn read_config_builds_only_a_configuration_naming_no_file() {
        let unbuilt = |rest: &str| format!("listen: ['127.0.0.1:53']\npipeline: []\n{rest}");
        let stage = |stage: &str| unbuilt(&format!("stages:\n  s:\n{stage}"));
        let naming = [
            unbuilt(
                "tls:\n  certificate: /nonexistent/cert.pem\n  key: /nonexistent/key.pem\nstages: {}\n",
            ),
            unbuilt("upstream_ca: /nonexistent/ca.pem\nstages: {}\n"),
            stage(
                "    type: forward\n    servers: ['192.0.2.1']\n    trust_anchors: /nonexistent/anchors\n",
            ),
            stage("    type: cache\n    prewarm:\n      file: /nonexistent/names\n"),
            stage("    type: hosts\n    file: /nonexistent/hosts\n"),
            stage("    type: blocklist\n    file: /nonexistent/list\n"),
            stage("    type: blocklist\n    urls: ['https://lists.example/list.txt']\n"),
            stage("    type: blocklist\n    allow:\n      file: /nonexistent/allow\n"),
            stage(
                "    type: blocklist\n    allow:\n      urls: ['https://lists.example/allow.txt']\n",
            ),
        ];
        for text in naming {
            assert!(super::read_config(&text, |_| None).is_ok(), "{text}");
        }
        let built = [
            unbuilt("stages: {}\n"),
            stage("    type: cache\n"),
            stage("    type: cache\n    prewarm:\n      entries: ['example.org']\n"),
            stage("    type: forward\n    servers: ['192.0.2.1']\n"),
            stage("    type: hosts\n"),
            stage("    type: blocklist\n    allow:\n      entries: ['example.org']\n"),
        ];
        for text in built {
            let error = super::read_config(&text, |_| None).expect_err(&text);
            assert_eq!(format!("{error:#}"), "`pipeline` has no stage", "{text}");
        }
    }
}
