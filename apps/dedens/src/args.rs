//! The command line (D32): dig's tokens turned into long flags, then clap.

use std::ffi::OsString;
use std::net::IpAddr;
use std::num::NonZeroU8;
use std::path::PathBuf;

use clap::{Args, Parser, ValueEnum};
use dedens_scenario::{CookieOption, Options, Timeout};

/// A dig-like DNS client.
///
/// dig's syntax works too: `@server` is `--server server`, `+opt` is `--opt`, `+noopt` is `--opt=false` and
/// `+opt=value` is `--opt=value`.
#[derive(Debug, Parser)]
#[command(version, max_term_width = 100)]
pub(crate) struct Cli {
    /// Names, types and classes, as dig reads them: a type or class mnemonic is one, anything else a name. Each
    /// name is asked the types after it, else those before the first name, else A; no name asks NS of the root.
    #[arg(value_name = "NAME|TYPE|CLASS")]
    pub(crate) words: Vec<String>,
    /// The server: an address, with or without a port, or a host name. Default: the first `nameserver` of
    /// /etc/resolv.conf.
    #[arg(long, value_name = "SERVER")]
    pub(crate) server: Option<String>,
    /// Ask PTR for the reverse name of an address (RFC 1035 §3.5, RFC 3596 §2.5).
    #[arg(short = 'x', value_name = "ADDR")]
    pub(crate) reverse: Vec<IpAddr>,
    /// Run the queries of a query file, `-` for stdin, and check their expectations.
    #[arg(short = 'f', long, value_name = "FILE")]
    pub(crate) file: Option<PathBuf>,
    /// The format of the query file. Default: by its extension, else YAML.
    #[arg(long, value_enum, requires = "file")]
    pub(crate) format: Option<FileFormat>,
    /// Run only the queries of the file with this id.
    #[arg(long, value_name = "ID", requires = "file")]
    pub(crate) only: Vec<String>,
    /// Write each response to `DIR/<id>.bin`, as received.
    #[arg(long, value_name = "DIR")]
    pub(crate) save_wire: Option<PathBuf>,
    /// Try a name under the search list of /etc/resolv.conf until one is not NXDOMAIN, as dig.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "false")]
    pub(crate) search: bool,
    #[command(flatten)]
    pub(crate) options: QueryOptions,
    #[command(flatten)]
    pub(crate) output: Output,
}

/// The output.
#[derive(Debug, Args)]
pub(crate) struct Output {
    /// Only the data of the answer records.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "false")]
    pub(crate) short: bool,
    /// dig's layout.
    #[arg(long, conflicts_with = "short")]
    pub(crate) dig: bool,
    /// One JSON object per query and line.
    #[arg(long, conflicts_with_all = ["short", "dig"])]
    pub(crate) json: bool,
    /// Colors: `NO_COLOR` turns them off for `auto`.
    #[arg(long, value_enum, default_value_t = clap::ColorChoice::Auto)]
    pub(crate) color: clap::ColorChoice,
}

/// The format of a query file.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum FileFormat {
    /// JSON.
    Json,
    /// YAML.
    Yaml,
}

/// The query options, over those of a query file (D34).
#[derive(Debug, Args)]
pub(crate) struct QueryOptions {
    /// TCP from the start. Default: UDP, then TCP on a truncated response.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    tcp: Option<bool>,
    /// Keep a truncated UDP response instead of asking again over TCP.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    ignore: Option<bool>,
    /// Recursion desired (RD). Default: on.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    recurse: Option<bool>,
    /// Checking disabled (CD).
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    cd: Option<bool>,
    /// Authentic data wanted (AD). Default: on.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    ad: Option<bool>,
    /// EDNS. Default: on.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    edns: Option<bool>,
    /// The UDP payload size advertised with EDNS. Default: 1232.
    #[arg(long, value_name = "BYTES")]
    bufsize: Option<u16>,
    /// DNSSEC records wanted (DO).
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    dnssec: Option<bool>,
    /// Ask the server's identifier (NSID).
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    nsid: Option<bool>,
    /// The cookie: true, false, or a client cookie in hex (16 digits), then optionally a server cookie. Default: on.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", value_name = "COOKIE")]
    cookie: Option<CookieOption>,
    /// How long to wait for each response: seconds, or `500ms`. Default: 5.
    #[arg(long, value_name = "TIME")]
    time: Option<Timeout>,
    /// Queries sent before giving up. Default: 3.
    #[arg(long, value_name = "N")]
    tries: Option<NonZeroU8>,
}

impl From<&QueryOptions> for Options {
    fn from(o: &QueryOptions) -> Self {
        Self {
            tcp: o.tcp,
            ignore: o.ignore,
            recurse: o.recurse,
            cd: o.cd,
            ad: o.ad,
            edns: o.edns,
            bufsize: o.bufsize,
            dnssec: o.dnssec,
            nsid: o.nsid,
            cookie: o.cookie,
            timeout: o.time,
            tries: o.tries,
        }
    }
}

impl Cli {
    /// Parses the command line, dig's tokens included; exits with code 2 on a usage error.
    pub(crate) fn parse_dig(args: impl IntoIterator<Item = OsString>) -> Self {
        Self::parse_from(args.into_iter().flat_map(long_flags))
    }
}

/// dig's tokens as long flags: `@srv` → `--server srv`, `+opt` → `--opt`, `+noopt` → `--opt=false`,
/// `+opt=v` → `--opt=v`. Any other argument, and one that is not UTF-8, stays.
fn long_flags(arg: OsString) -> Vec<OsString> {
    let Some(text) = arg.to_str() else {
        return vec![arg];
    };
    if let Some(server) = text.strip_prefix('@') {
        return vec!["--server".into(), server.into()];
    }
    let Some(option) = text.strip_prefix('+') else {
        return vec![arg];
    };
    let flag = match option.strip_prefix("no") {
        Some(name) if !option.contains('=') && !name.is_empty() => format!("--{name}=false"),
        _ => format!("--{option}"),
    };
    vec![flag.into()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dig_tokens_become_long_flags() {
        for (token, flags) in [
            ("@1.1.1.1", &["--server", "1.1.1.1"][..]),
            ("+tcp", &["--tcp"]),
            ("+notcp", &["--tcp=false"]),
            ("+bufsize=512", &["--bufsize=512"]),
            ("+nsid", &["--nsid"]),
            ("example.com", &["example.com"]),
            ("-x", &["-x"]),
        ] {
            let flags: Vec<OsString> = flags.iter().map(OsString::from).collect();
            assert_eq!(long_flags(token.into()), flags, "{token}");
        }
    }

    #[test]
    fn clap_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
