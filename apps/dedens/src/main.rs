//! `dedens`: a dig-like DNS client (D18, D32).
//!
//! Exit codes (D33): 0 a response came, whatever its rcode; 1 an expectation failed; 2 usage; 9 no reply; 10 any
//! other error.

#![forbid(unsafe_code)]

// D154: on musl, mimalloc in its secure mode replaces musl's allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod args;
mod idn;
mod output;
mod run;
mod trace;
mod validate;

use std::ffi::OsStr;
use std::io::{self, IsTerminal};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = args::Cli::parse_dig(std::env::args_os());
    diagnostics(&cli);
    run::run(&cli).unwrap_or_else(|error| {
        eprintln!("dedens: {error:#}");
        ExitCode::from(10)
    })
}

/// Prints the `tracing` events of `-v` (debug) and `-vv` (trace) on stderr, as text (D30).
fn diagnostics(cli: &args::Cli) {
    let level = match cli.verbose {
        0 => return,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    let ansi = match cli.output.color {
        clap::ColorChoice::Always => true,
        clap::ColorChoice::Never => false,
        clap::ColorChoice::Auto => colored(
            io::stderr().is_terminal(),
            std::env::var_os("NO_COLOR").as_deref(),
        ),
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr)
        .with_ansi(ansi)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();
}

/// Whether `--color auto` colours the events: on a `terminal`, unless `NO_COLOR` is set to a value (D169).
fn colored(terminal: bool, no_color: Option<&OsStr>) -> bool {
    terminal && no_color.is_none_or(OsStr::is_empty)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::colored;

    /// Events are coloured on a terminal only, and not even there once `NO_COLOR` is set to a value; set empty, it
    /// is as unset (no-color.org), as for the output on stdout.
    #[test]
    fn events_are_coloured_on_a_terminal_without_no_color() {
        assert!(colored(true, None));
        assert!(!colored(false, None));
        assert!(!colored(true, Some(OsStr::new("1"))));
        assert!(!colored(false, Some(OsStr::new("1"))));
        assert!(colored(true, Some(OsStr::new(""))));
        assert!(!colored(false, Some(OsStr::new(""))));
    }
}
