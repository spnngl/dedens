//! `dedens`: a dig-like DNS client (D18, D32), a library the binary and `fuzz/` reach (D181): [`main`] runs the command,
//! [`parse_args`] only reads its command line.
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

use std::ffi::OsString;
use std::io;
use std::process::ExitCode;

/// Runs `dedens` on the process's command line: its exit code (D33). Exits at once, code 2, on a usage error of the
/// command line itself.
#[must_use]
pub fn main() -> ExitCode {
    let cli = args::Cli::parse_dig(std::env::args_os());
    diagnostics(&cli);
    run::run(&cli).unwrap_or_else(|error| {
        eprintln!("dedens: {error:#}");
        ExitCode::from(if error.is::<run::Usage>() { 2 } else { 10 })
    })
}

/// Reads `args`, a command line with the program's name first, as [`main`] does, without running it: the entry of
/// `fuzz/` (D181).
///
/// # Errors
///
/// A usage error, which [`main`] prints before it exits with code 2.
pub fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<(), clap::Error> {
    let cli = args::Cli::try_parse_dig(args)?;
    args::lookups(&cli.words, !cli.reverse.is_empty());
    Ok(())
}

/// Prints the `tracing` events of `-v` (debug) and `-vv` (trace) on stderr, as text (D30).
fn diagnostics(cli: &args::Cli) {
    let level = match cli.verbose {
        0 => return,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    // Coloured as stdout is, by anstream (D169): `--color`, then `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`, `TERM`.
    let ansi = anstream::AutoStream::new(io::stderr(), cli.output.color()).current_choice()
        != anstream::ColorChoice::Never;
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr)
        .with_ansi(ansi)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();
}

#[cfg(test)]
mod tests {
    /// D181: the entry of `fuzz/` reads a command line as `main` does, and refuses what it refuses.
    #[test]
    fn parse_args_refuses_what_main_refuses() {
        let parse = |words: &[&str]| super::parse_args(words.iter().map(super::OsString::from));
        assert!(parse(&["dedens", "example.com", "+tries=2"]).is_ok());
        assert!(parse(&["dedens", "example.com", "+tries=many"]).is_err());
    }
}
