//! What the server says of itself: its `tracing` events on stderr, as JSON or text (D30), and the start's
//! "serving" event with the driver its threads run on, warning of `poll` on Linux (D107), and of CoAP (RFC 9953 §6).

use std::ffi::OsStr;
use std::io::{self, IsTerminal};

use clap::ValueEnum;
use compio::driver::DriverType;

use crate::config::Listen;

/// How events are written on stderr (`--log-format`).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum LogFormat {
    Json,
    Text,
}

/// Prints `tracing` events on stderr, in `format`: info, debug with `-v`, trace with `-vv` (D30).
pub(crate) fn diagnostics(verbose: u8, format: LogFormat) {
    let events = tracing_subscriber::fmt()
        .with_max_level(level(verbose))
        .with_writer(io::stderr);
    match format {
        LogFormat::Json => events.json().init(),
        LogFormat::Text => events
            .with_ansi(colored(
                io::stderr().is_terminal(),
                std::env::var_os("NO_COLOR").as_deref(),
            ))
            .init(),
    }
}

/// The most detailed events printed for `verbose`, the count of `-v`: info, debug with `-v`, trace with `-vv`.
fn level(verbose: u8) -> tracing::Level {
    match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    }
}

/// Whether text events are coloured: on a `terminal`, unless `NO_COLOR` is set to a value (D169).
fn colored(terminal: bool, no_color: Option<&OsStr>) -> bool {
    terminal && no_color.is_none_or(OsStr::is_empty)
}

/// Logs that the server is serving `listen`, on the `drivers` of its threads, and warns of a driver that is a loss.
pub(crate) fn announce(config: &str, listen: &[Listen], drivers: &[DriverType]) {
    let (driver, threads) = (Driver::of(drivers), drivers.len());
    tracing::info!(config, ?listen, threads, driver = driver.name, "serving");
    if let Some(warning) = driver.warning(cfg!(target_os = "linux")) {
        tracing::warn!(driver = driver.name, threads, "{warning}");
    }
}

/// Warns of each CoAP address in `listen`: DNS there is unprotected (RFC 9953 §6).
#[cfg(feature = "doc")]
pub(crate) fn warn_coap(listen: &[Listen]) {
    for listen in listen.iter().filter(|l| matches!(l, Listen::Coap(..))) {
        tracing::warn!(
            ?listen,
            "CoAP is unprotected, NOT RECOMMENDED (RFC 9953 §6)"
        );
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

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use compio::driver::DriverType::{IoUring, Poll};
    use tracing::Level;

    use super::{Driver, colored, level};

    /// Info by default, debug with `-v`, trace with `-vv` or more.
    #[test]
    fn each_v_prints_more_detail() {
        let levels: Vec<_> = (0..=3).map(level).collect();
        assert_eq!(
            levels,
            [Level::INFO, Level::DEBUG, Level::TRACE, Level::TRACE]
        );
    }

    /// Text is coloured on a terminal only, and not even there once `NO_COLOR` is set to a value; set empty, it is
    /// as unset (no-color.org).
    #[test]
    fn text_is_coloured_on_a_terminal_without_no_color() {
        assert!(colored(true, None));
        assert!(!colored(false, None));
        assert!(!colored(true, Some(OsStr::new("1"))));
        assert!(!colored(false, Some(OsStr::new("1"))));
        assert!(colored(true, Some(OsStr::new(""))));
        assert!(!colored(false, Some(OsStr::new(""))));
    }

    /// D107: a Linux server on `poll` warns, a server on `io_uring` or elsewhere does not; the threads' drivers are
    /// one name, `mixed` when they differ, `none` without threads.
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
        assert_eq!(Driver::of(&[]).name, "none");
    }
}
