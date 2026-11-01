//! `dedens`: a dig-like DNS client (D18, D32).
//!
//! Exit codes (D33): 0 a response came, whatever its rcode; 1 an expectation failed; 2 usage; 9 no reply; 10 any
//! other error.

#![forbid(unsafe_code)]

mod args;
mod idn;
mod output;
mod run;
mod trace;
mod validate;

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
        clap::ColorChoice::Auto => {
            io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
        }
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr)
        .with_ansi(ansi)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();
}
