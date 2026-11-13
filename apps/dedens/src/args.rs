//! The command line (D32): dig's tokens turned into long flags, then clap; the words turned into questions.

use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::builder::NonEmptyStringValueParser;
use clap::error::ErrorKind;
use clap::{Arg, Args, CommandFactory, FromArgMatches, Parser};
use compio::rustls::pki_types::CertificateDer;
use compio::rustls::pki_types::pem::PemObject;
use dedens_net::tls::Trust;
use dedens_proto::{Class, RecordType};
use dedens_scenario::{Id, Options};

use crate::output::Format;
use crate::run::refuse_conflicts;

/// A dig-like DNS client.
///
/// dig's syntax works too: `@server` is `--server server`, `+opt` is `--opt`, `+noopt` is `--opt=false` and
/// `+opt=value` is `--opt=value`, `opt` any unique prefix of a long flag; `-t TYPE`, `-c CLASS` and `-q NAME`
/// are words.
#[derive(Debug, Parser)]
#[command(version, max_term_width = 100)]
pub(crate) struct Cli {
    /// Names, types and classes, as dig reads them: a type or class mnemonic is one, anything else a name. Each
    /// name is asked the types after it, else those before the first name, else A; no name asks NS of the root.
    #[arg(value_name = "NAME|TYPE|CLASS")]
    pub(crate) words: Vec<String>,
    /// A server: an address, with or without a port, or a host name; `tls://`, `quic://` or `https://HOST/PATH` before
    /// it for DNS over TLS, QUIC or HTTPS, `coap://HOST/PATH` for DNS over CoAP, `sdns://…` for the `DNSCrypt` resolver
    /// of a DNS stamp (a build with the `dnscrypt` feature). Each query is asked of each, side by side. Default: the
    /// first `nameserver` of /etc/resolv.conf.
    #[arg(long, value_name = "SERVER", value_parser = NonEmptyStringValueParser::new())]
    server: Vec<String>,
    /// The port of a server given without one, a stamp having its own. Default: 443 over HTTPS, 5683 over CoAP, 853
    /// over TLS or QUIC, else 53.
    #[arg(short, long, value_name = "PORT")]
    pub(crate) port: Option<u16>,
    /// Trust the certificate authorities of this PEM file over TLS, instead of the system's.
    #[arg(long, value_name = "FILE")]
    tls_ca: Option<PathBuf>,
    /// Accept any server certificate over TLS, unverified: the connection is encrypted, the server unknown.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "false", conflicts_with = "tls_ca")]
    tls_insecure: bool,
    /// Ask PTR for the reverse name of an address (RFC 1035 §3.5, RFC 3596 §2.5).
    #[arg(short = 'x', value_name = "ADDR")]
    pub(crate) reverse: Vec<IpAddr>,
    /// Run the queries of a query file, YAML or JSON, `-` for stdin, and check their expectations.
    #[arg(short = 'f', long, value_name = "FILE", conflicts_with_all = ["words", "reverse", "search"])]
    pub(crate) file: Option<PathBuf>,
    /// Run only the queries of the file with this id.
    #[arg(long, value_name = "ID", requires = "file")]
    pub(crate) only: Vec<Id>,
    /// Write each response to `DIR/<id>.bin`, as received.
    #[arg(long, value_name = "DIR")]
    pub(crate) save_wire: Option<PathBuf>,
    /// Ask each query this many times in a row, then print its last response and the spread of round trips.
    #[arg(long, value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) repeat: u16,
    /// Follow each query from the root servers down the referrals, printing every response, as dig.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "false")]
    pub(crate) trace: bool,
    /// Try a name under the search list of /etc/resolv.conf until one is not NXDOMAIN, as dig.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "false")]
    pub(crate) search: bool,
    /// Print what the exchanges do on stderr: `-v` dropped messages, retries and fallbacks, `-vv` every message too.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,
    #[command(flatten)]
    pub(crate) options: Options,
    #[command(flatten)]
    pub(crate) output: Output,
}

/// The output.
#[derive(Debug, Args)]
pub(crate) struct Output {
    /// The output format.
    #[arg(long, value_enum)]
    format: Option<Format>,
    /// `--format short`.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "false")]
    short: bool,
    /// `--format json`.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "false")]
    json: bool,
    /// `--format yaml`.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "false")]
    yaml: bool,
    /// Colors: `NO_COLOR` turns them off for `auto`.
    #[arg(long, value_enum, default_value_t = clap::ColorChoice::Auto)]
    color: clap::ColorChoice,
}

impl Output {
    /// The format asked for, by `--format` or one of its shorthands.
    pub(crate) fn format(&self) -> Format {
        match self {
            Self { short: true, .. } => Format::Short,
            Self { json: true, .. } => Format::Json,
            Self { yaml: true, .. } => Format::Yaml,
            Self { format, .. } => format.unwrap_or(Format::Human),
        }
    }

    /// The colours of `--color`, for anstream, which reads the environment's choice for `auto` (D169).
    pub(crate) const fn color(&self) -> anstream::ColorChoice {
        match self.color {
            clap::ColorChoice::Auto => anstream::ColorChoice::Auto,
            clap::ColorChoice::Always => anstream::ColorChoice::Always,
            clap::ColorChoice::Never => anstream::ColorChoice::Never,
        }
    }
}

impl Cli {
    /// Parses the command line, dig's tokens included; exits with code 2 on a usage error.
    pub(crate) fn parse_dig(args: impl IntoIterator<Item = OsString>) -> Self {
        Self::try_parse_dig(args).unwrap_or_else(|error| error.exit())
    }

    /// [`Self::parse_dig`], returning the usage error instead of exiting with it.
    pub(crate) fn try_parse_dig(
        args: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, clap::Error> {
        let usage = |kind, message: String| Err(Self::command().error(kind, message));
        let mut command = Self::command();
        command.build();
        let args = match long_flags(&command, args) {
            Ok(args) => args,
            Err(error) => return usage(ErrorKind::UnknownArgument, error),
        };
        // Parsed by the command `long_flags` read: built once, not again by `try_parse_from`.
        let mut matches = command.try_get_matches_from_mut(args)?;
        let cli = Self::from_arg_matches_mut(&mut matches).map_err(|e| e.format(&mut command))?;
        // Checked here, on the values: clap would refuse `+notrace` or `+nojson` with them, given as `--trace=false`.
        if cli.trace
            && (!cli.server.is_empty()
                || cli.file.is_some()
                || cli.repeat > 1
                || cli.search
                || cli.options.encrypted()
                || cli.options.https()
                || cli.options.odoh()
                || cli.options.coap == Some(true)
                || cli.options.dnscrypt()
                || cli.options.validating())
        {
            return usage(
                ErrorKind::ArgumentConflict,
                "+trace goes with no @server, -f, +repeat, +search, +tls, +quic, +https, +odoh-proxy, +coap, +dnscrypt-cert, +dnscrypt-pq, +dnscrypt-resume or +validate"
                    .to_owned(),
            );
        }
        for server in &cli.server {
            if let Err(error) = refuse_conflicts(server, &cli.options) {
                return usage(ErrorKind::ArgumentConflict, error.to_string());
            }
        }
        // The target of Oblivious DoH is a server of the command line; a query file names its own.
        let https = |server: &String| server.starts_with("https://");
        if cli.options.odoh() && cli.file.is_none() && !cli.server.iter().any(https) {
            return usage(
                ErrorKind::ArgumentConflict,
                "+odoh-proxy needs an https:// target @server".to_owned(),
            );
        }
        let stamp = |server: &String| server.starts_with("sdns://");
        if cli.options.dnscrypt()
            && cli.file.is_none()
            && (cli.server.is_empty() || !cli.server.iter().all(stamp))
        {
            return usage(
                ErrorKind::ArgumentConflict,
                "+dnscrypt-cert, +dnscrypt-pq and +dnscrypt-resume need an sdns:// @server"
                    .to_owned(),
            );
        }
        if !cli.discovers_where_it_can() {
            return usage(
                ErrorKind::ArgumentConflict,
                "+doc-discover needs a CoAP server (+coap or coap://) with no path".to_owned(),
            );
        }
        let output = &cli.output;
        if [
            output.format.is_some(),
            output.short,
            output.json,
            output.yaml,
        ]
        .into_iter()
        .filter(|&set| set)
        .count()
            > 1
        {
            return usage(
                ErrorKind::ArgumentConflict,
                "one of --format, --short, --json and --yaml at most".to_owned(),
            );
        }
        if let Err(error) = cli.options.check() {
            return usage(ErrorKind::ArgumentConflict, error.to_string());
        }
        Ok(cli)
    }

    /// Whether `+doc-discover`, if given, has a CoAP server to ask with no path of its own: the resource is found at
    /// the server (D95). A query file names its own servers, which the run checks.
    fn discovers_where_it_can(&self) -> bool {
        if self.options.doc_discover != Some(true) || self.file.is_some() {
            return true;
        }
        let coap_on = self.options.coap == Some(true);
        let discoverable = |server: &String| match server.strip_prefix("coap://") {
            // `coap://HOST/` is the root path, no path at all (RFC 7252 §6.4), as the run reads it.
            Some(host) => host.split_once('/').is_none_or(|(_, path)| path.is_empty()),
            None => coap_on && !server.contains("://"),
        };
        if self.server.is_empty() {
            coap_on
        } else {
            self.server.iter().all(discoverable)
        }
    }

    /// The servers given, in order.
    pub(crate) fn servers(&self) -> &[String] {
        &self.server
    }

    /// The server certificates to accept over TLS.
    ///
    /// # Errors
    ///
    /// The file of `--tls-ca` cannot be read or holds no certificate.
    pub(crate) fn trust(&self) -> anyhow::Result<Trust> {
        if self.tls_insecure {
            return Ok(Trust::Anyone);
        }
        let Some(path) = &self.tls_ca else {
            return Ok(Trust::System);
        };
        let certificates = CertificateDer::pem_file_iter(path)
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            .with_context(|| format!("cannot read certificates from {}", path.display()))?;
        if certificates.is_empty() {
            bail!("no certificate in {}", path.display());
        }
        Ok(Trust::Roots(certificates))
    }
}

/// The names of `words` with the types to ask each, and the class: each name the types after it, else those
/// before the first name, else A. Without a name, and without `-x` (`reverse`), the root is asked NS, as in dig.
pub(crate) fn lookups(words: &[String], reverse: bool) -> (Vec<(&str, Vec<RecordType>)>, Class) {
    let (mut leading, mut names, mut class) = (Vec::new(), Vec::<(&str, Vec<_>)>::new(), Class::IN);
    for word in words {
        match (word.parse(), word.parse()) {
            (Ok(qtype), _) => names
                .last_mut()
                .map_or(&mut leading, |(_, types)| types)
                .push(qtype),
            (_, Ok(qclass)) => class = qclass,
            _ => names.push((word.as_str(), Vec::new())),
        }
    }
    if names.is_empty() && !reverse {
        names.push((".", Vec::new()));
        if leading.is_empty() {
            leading.push(RecordType::NS);
        }
    }
    if leading.is_empty() {
        leading.push(RecordType::A);
    }
    for (_, types) in &mut names {
        if types.is_empty() {
            types.clone_from(&leading);
        }
    }
    (names, class)
}

/// The arguments with dig's tokens as long flags and words. `@srv` → `--server srv`; `+opt` → `--opt`, `+noopt`
/// → `--opt=false` for an on/off flag, `+opt=v` → `--opt=v`, `opt` a unique prefix; `-t TYPE`, `-c CLASS` and
/// `-q NAME` → the word, a name that reads as a mnemonic made absolute. The value of a flag that takes one, any
/// argument after `--`, and one that is not UTF-8 stay as they are.
fn long_flags(
    command: &clap::Command,
    args: impl IntoIterator<Item = OsString>,
) -> Result<Vec<OsString>, String> {
    let mut args = args.into_iter();
    let mut out: Vec<OsString> = args.next().into_iter().collect();
    while let Some(arg) = args.next() {
        let Some(text) = arg.to_str() else {
            out.push(arg);
            continue;
        };
        if text == "--" {
            out.push(arg);
            out.extend(args);
            break;
        }
        if let Some(server) = text.strip_prefix('@') {
            out.extend(["--server".into(), server.into()]);
        } else if let Some(option) = text.strip_prefix('+') {
            out.push(plus(command, option)?.into());
        } else if let Some(rest) = text.strip_prefix('-')
            && let Some(letter @ ('t' | 'c' | 'q')) = rest.chars().next()
        {
            let value = match &rest[1..] {
                "" => args
                    .next()
                    .and_then(|v| v.into_string().ok())
                    .ok_or(format!("{text}: a value is needed"))?,
                attached => attached.to_owned(),
            };
            out.push(word(letter, value)?.into());
        } else {
            let takes_value = flag(command, text)
                .and_then(Arg::get_num_args)
                .is_some_and(|n| n.min_values() > 0);
            out.push(arg);
            if takes_value {
                out.extend(args.next());
            }
        }
    }
    Ok(out)
}

/// The long flag of `+option`, which is `name`, `noname` or `name=value`.
fn plus(command: &clap::Command, option: &str) -> Result<String, String> {
    let (name, value) = match option.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (option, None),
    };
    let negated = name
        .strip_prefix("no")
        .filter(|_| value.is_none())
        .and_then(|rest| long(command, rest).ok());
    let (arg, value) = match negated {
        Some(arg) if on_off(arg) => (arg, Some("false")),
        Some(arg) => return Err(format!("+{name}: --{} is not on/off", long_name(arg))),
        None => (long(command, name)?, value),
    };
    Ok(match value {
        Some(value) => format!("--{}={value}", long_name(arg)),
        None => format!("--{}", long_name(arg)),
    })
}

/// The flag whose long name is `prefix`, else the only one starting with it.
fn long<'c>(command: &'c clap::Command, prefix: &str) -> Result<&'c Arg, String> {
    let named = || command.get_arguments().filter(|a| a.get_long().is_some());
    if let Some(exact) = named().find(|a| a.get_long() == Some(prefix)) {
        return Ok(exact);
    }
    let mut matching = named().filter(|a| !prefix.is_empty() && long_name(a).starts_with(prefix));
    match (matching.next(), matching.next()) {
        (Some(arg), None) => Ok(arg),
        (None, _) => Err(format!("+{prefix}: unknown option")),
        (Some(first), Some(second)) => Err(format!(
            "+{prefix}: ambiguous, --{} or --{}…",
            long_name(first),
            long_name(second)
        )),
    }
}

fn long_name(arg: &Arg) -> &str {
    arg.get_long().unwrap_or_default()
}

/// Whether `arg` is an on/off flag: one whose value may be left out, for `true`.
fn on_off(arg: &Arg) -> bool {
    arg.get_num_args()
        .is_some_and(|n| n.min_values() == 0 && n.max_values() == 1)
}

/// The flag `text` is, `--name` or `-n`, without a value attached.
fn flag<'c>(command: &'c clap::Command, text: &str) -> Option<&'c Arg> {
    if let Some(name) = text.strip_prefix("--") {
        return command.get_arguments().find(|a| a.get_long() == Some(name));
    }
    let mut letters = text.strip_prefix('-')?.chars();
    let (Some(letter), None) = (letters.next(), letters.next()) else {
        return None;
    };
    command
        .get_arguments()
        .find(|a| a.get_short() == Some(letter))
}

/// The word of `-t`, `-c` or `-q` (`letter`) and its `value`. A class that is also a type, as `ANY`, becomes its
/// generic form, `CLASS255`, which [`lookups`] cannot take for a type.
fn word(letter: char, value: String) -> Result<String, String> {
    let qtype = value.parse::<RecordType>().is_ok();
    let qclass = value.parse::<Class>();
    match (letter, qclass) {
        ('t', _) if !qtype => Err(format!("-t {value}: not a type")),
        ('c', Err(_)) => Err(format!("-c {value}: not a class")),
        ('c', Ok(class)) if qtype => Ok(format!("CLASS{}", class.0)),
        ('q', qclass) if qtype || qclass.is_ok() => Ok(value + "."),
        _ => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(args: &[&str]) -> Result<Vec<String>, String> {
        let mut command = Cli::command();
        command.build();
        let args = ["dedens"].iter().chain(args).map(OsString::from);
        let out = long_flags(&command, args)?;
        Ok(out[1..]
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect())
    }

    #[test]
    fn dig_tokens_become_long_flags() {
        for (args, flags) in [
            (&["@1.1.1.1"][..], &["--server", "1.1.1.1"][..]),
            (&["+tcp"], &["--tcp"]),
            (&["+notcp"], &["--tcp=false"]),
            (&["+norec"], &["--recurse=false"]),
            (&["+nocd"], &["--cdflag=false"]),
            (&["+sh"], &["--short"]),
            (&["+nojson"], &["--json=false"]),
            (&["+bufsize=512"], &["--bufsize=512"]),
            (&["+validate"], &["--validate"]),
            (&["+novalidate"], &["--validate=false"]),
            (&["+trust-anchor=a.zone"], &["--trust-anchor=a.zone"]),
            (&["+insecure=example.com"], &["--insecure=example.com"]),
            (&["+save-wire=dir"], &["--save-wire=dir"]),
            (&["--only", "@x", "+nsid"], &["--only", "@x", "--nsid"]),
            (&["-f", "+x"], &["-f", "+x"]),
            (&["--file", "+x"], &["--file", "+x"]),
            (&["--tcp", "+short"], &["--tcp", "--short"]),
            (&["--", "+x", "@y"], &["--", "+x", "@y"]),
            (&["-t", "MX", "-cCH"], &["MX", "CH"]),
            (&["-q", "example.com", "-q", "MX"], &["example.com", "MX."]),
            (
                &["-p", "5353", "-x", "192.0.2.1"],
                &["-p", "5353", "-x", "192.0.2.1"],
            ),
            (&["example.com"], &["example.com"]),
        ] {
            assert_eq!(
                rewrite(args),
                Ok(flags.iter().map(ToString::to_string).collect()),
                "{args:?}"
            );
        }
    }

    #[test]
    fn unknown_ambiguous_and_valued_negations_are_refused() {
        for args in [
            &["+bogus"][..],
            &["+t"],
            &["+"],
            &["+nosave-wire"],
            &["+noserver"],
            &["-t", "example.com"],
            &["-c", "MX"],
            &["-t"],
        ] {
            assert!(rewrite(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn words_become_lookups() {
        use RecordType as T;
        type Case = (
            &'static [&'static str],
            bool,
            &'static [(&'static str, &'static [T])],
            Class,
        );
        let cases: [Case; 6] = [
            (&[], false, &[(".", &[T::NS])], Class::IN),
            (&["MX"], false, &[(".", &[T::MX])], Class::IN),
            (&[], true, &[], Class::IN),
            (
                &["example.com"],
                false,
                &[("example.com", &[T::A])],
                Class::IN,
            ),
            (
                &["TXT", "a.example", "b.example", "MX", "AAAA"],
                false,
                &[("a.example", &[T::TXT]), ("b.example", &[T::MX, T::AAAA])],
                Class::IN,
            ),
            (
                &["CH", "TXT", "version.bind"],
                true,
                &[("version.bind", &[T::TXT])],
                Class::CH,
            ),
        ];
        for (words, reverse, names, class) in cases {
            let words: Vec<String> = words.iter().map(ToString::to_string).collect();
            let (got, got_class) = lookups(&words, reverse);
            let expected: Vec<(&str, Vec<T>)> =
                names.iter().map(|(n, t)| (*n, t.to_vec())).collect();
            assert_eq!((got, got_class), (expected, class), "{words:?}");
        }
    }

    /// `-c ANY` asks class ANY, as dig does, though `ANY` alone is the type.
    #[test]
    fn dash_c_any_is_the_class() {
        let words = rewrite(&["-c", "ANY", "example.com"]).expect("rewritten");
        assert_eq!(
            lookups(&words, false),
            (vec![("example.com", vec![RecordType::A])], Class::ANY)
        );
    }

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// D158: the packaged man page is this command line's, without the version, which the package has; `just man`
    /// writes it again.
    #[test]
    fn the_man_page_is_the_command_lines() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/packages/man/dedens.1"
        );
        let mut page = Vec::new();
        clap_mangen::Man::new(Cli::command().version(None::<&str>))
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
