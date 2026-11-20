//! `${VAR}` in the configuration (D44, D115): each placeholder replaced by its variable's value as YAML text, never
//! as YAML.

use std::mem;

use anyhow::{Context, bail, ensure};

/// `text` with each `${VAR}` replaced by the variable's value, written so that it is one value, never YAML
/// ([`written`], D115), `${VAR:-default}` by `default` as written when it is unset or empty, and `$$` by `$`; any
/// other `$` stays, and so does a line whose first non-blank character is `#`, a comment.
///
/// # Errors
///
/// A variable without a value or default, one whose value [`written`] refuses, or a `${` left open on its line.
pub(super) fn interpolate(
    text: &str,
    env: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut scan = Scan::default();
    for line in text.split_inclusive('\n') {
        scan.line(line);
        if line.trim_start().starts_with('#') {
            out.push_str(line);
            scan.feed(line);
        } else {
            interpolate_line(line, &env, &mut scan, &mut out)?;
        }
    }
    Ok(out)
}

/// A quoted scalar of the template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quote {
    Single,
    Double,
}

/// Where a placeholder stands in the YAML of the template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// Where a scalar may start, `flow` inside a flow collection or not.
    Start { flow: bool },
    /// Inside a quoted scalar.
    Quoted(Quote),
    /// Anywhere else: within a plain scalar, a comment or a block scalar's text, or after a quote that starts no
    /// scalar.
    Other,
}

/// What the last character outside quotes, a scalar's first if a space follows, makes of that space.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Pending {
    #[default]
    None,
    /// `-`, `?` or `:`: an indicator, a scalar may start after the space.
    Indicator,
    /// The `!` of a tag or the `&` of an anchor: so is the rest up to the space.
    Property,
}

/// The template's YAML as far as [`Place`] needs it, every placeholder taken for text of a scalar: the quoted
/// scalar open, how deep in flow collections, across lines (D115). A quote opens a quoted scalar only where a
/// scalar may start (a line's start, after `- `, `? `, `: `, a tag or an anchor, after `[`, `{` or `,` in a flow);
/// elsewhere it is text, and the rest of its line [`Place::Other`]. A line more indented than the scalar it may
/// continue, or any line in a flow, continues it; the lines more indented than one ending in `|` or `>` are the
/// text of a block scalar.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is a fact of the YAML read so far, independent of the others"
)]
struct Scan {
    quote: Option<Quote>,
    /// A single quote just closed the quoted scalar, unless the next character is one too: `''` is a quote.
    reopen: bool,
    /// After a `\` in double quotes.
    escaped: bool,
    /// Flow collections open.
    flow: usize,
    /// A scalar may start at the next character.
    start: bool,
    pending: Pending,
    /// The last character closed a quoted scalar or a flow collection: in a flow, a `:` right after it is an
    /// indicator.
    closed: bool,
    /// The last character was a space, a tab or the line's start: a `#` there starts a comment.
    spaced: bool,
    /// In a comment, or after a quote that starts no scalar, up to the end of the line.
    lost: bool,
    /// The indentation of the line where the plain scalar open started.
    plain: Option<usize>,
    /// A `|` or `>` where a scalar may start on this line, a block scalar's header (no plain scalar starts with
    /// one), and the indentation of the line.
    header: Option<usize>,
    /// The indentation of the line ending in `|` or `>`, while the lines are the text of its block scalar.
    block: Option<usize>,
    /// The indentation of the line.
    indent: usize,
    /// The line is the text of a block scalar.
    text: bool,
}

impl Scan {
    /// Starts `line`, before its characters.
    fn line(&mut self, line: &str) {
        self.indent = line.len() - line.trim_start_matches(' ').len();
        self.reopen = false;
        if self.quote.is_some() {
            return;
        }
        let blank = line.trim().is_empty();
        self.text = self.block.is_some_and(|block| blank || self.indent > block);
        if !self.text {
            self.block = None;
        }
        // A blank line leaves a plain scalar open.
        if blank {
            return;
        }
        let continued = self
            .plain
            .is_some_and(|at| self.flow > 0 || self.indent > at);
        if !continued {
            self.plain = None;
        }
        self.start = !continued;
        self.pending = Pending::None;
        self.closed = false;
        self.spaced = true;
        self.lost = false;
        self.header = None;
    }

    /// Where a placeholder here stands.
    const fn place(&self) -> Place {
        if self.text || self.lost {
            return Place::Other;
        }
        match self.quote {
            Some(quote) => Place::Quoted(quote),
            None if self.start => Place::Start {
                flow: self.flow > 0,
            },
            None => Place::Other,
        }
    }

    /// Follows a placeholder's value: text of the scalar.
    const fn value(&mut self) {
        self.reopen = false;
        if !self.text && !self.lost && self.quote.is_none() {
            self.other();
        }
    }

    /// Follows the template's `text`.
    fn feed(&mut self, text: &str) {
        if !self.text {
            text.chars().for_each(|c| self.char(c));
        }
    }

    fn char(&mut self, c: char) {
        if mem::take(&mut self.reopen) && c == '\'' {
            self.quote = Some(Quote::Single);
            return;
        }
        match self.quote {
            Some(Quote::Single) => {
                if c == '\'' {
                    self.close();
                    self.reopen = true;
                }
                return;
            }
            Some(Quote::Double) => {
                if !mem::take(&mut self.escaped) {
                    match c {
                        '\\' => self.escaped = true,
                        '"' => self.close(),
                        _ => {}
                    }
                }
                return;
            }
            None => {}
        }
        let spaced = mem::replace(&mut self.spaced, matches!(c, ' ' | '\t'));
        if c == '\n' {
            if self.pending != Pending::None {
                self.plain = None;
            }
            if let Some(indent) = self.header {
                self.block = Some(indent);
                self.plain = None;
            }
            return;
        }
        if self.lost {
            return;
        }
        match c {
            ' ' | '\t' => {
                if self.pending != Pending::None {
                    self.pending = Pending::None;
                    self.start = true;
                    self.plain = None;
                }
                self.closed = false;
            }
            '#' if spaced => self.lost = true,
            '\'' | '"' if self.start => {
                self.quote = Some(if c == '\'' {
                    Quote::Single
                } else {
                    Quote::Double
                });
                self.start = false;
                self.plain = None;
            }
            '\'' | '"' => self.lost = true,
            '[' | '{' if self.start => {
                self.flow += 1;
                self.start = true;
                self.closed = false;
                self.plain = None;
            }
            ']' | '}' if self.flow > 0 => {
                self.flow -= 1;
                self.start = false;
                self.closed = true;
                self.plain = None;
            }
            ',' if self.flow > 0 => {
                self.start = true;
                self.closed = false;
                self.plain = None;
            }
            ':' => {
                let adjacent = self.closed && self.flow > 0;
                self.other();
                self.pending = Pending::Indicator;
                if adjacent {
                    self.start = true;
                    self.plain = None;
                }
            }
            '-' | '?' if self.start => {
                self.other();
                self.pending = Pending::Indicator;
            }
            '!' | '&' if self.start => {
                self.other();
                self.pending = Pending::Property;
            }
            '|' | '>' if self.start && self.flow == 0 => {
                self.other();
                self.header = Some(self.indent);
            }
            '+' | '-' | '0'..='9' if self.header.is_some() => {}
            _ => self.other(),
        }
    }

    /// A character of a plain scalar, maybe its first.
    const fn other(&mut self) {
        self.start = false;
        self.closed = false;
        self.spaced = false;
        if matches!(self.pending, Pending::Indicator) {
            self.pending = Pending::None;
        }
        if self.plain.is_none() {
            self.plain = Some(self.indent);
        }
    }

    /// Ends the quoted scalar open; `start` and `spaced` are false since its opening quote.
    const fn close(&mut self) {
        self.quote = None;
        self.closed = true;
    }
}

/// How the value of variable `name` is written where `${name}` stands, at `place` between `before` and `after`,
/// the rest of its line in the template: a value cannot add YAML of its own (D44, D115).
/// - A plain value, made of letters, digits and `_./:@+=%~#-` that YAML cannot read as syntax (it does not start
///   with `#`, `@`, `%`, `---`, `...` or end with `:`, and is not `-` or `?`), is written as it is: ports,
///   addresses, paths and URLs stay usable anywhere, in a number or in a quoted text.
/// - Inside quotes of the template, right between two of them, it is escaped for them.
/// - Alone as a value (a whole scalar: where one may start, before a `,`, a `]`, a `}` in a flow, a `: `, a comment
///   or the end of the line), it is written in single quotes; so is a plain value YAML reads as null (`~`,
///   `null`, `Null`, `NULL`), which would otherwise read as no value.
///
/// # Errors
///
/// A value spanning lines (`\n` or `\r`), with another control character or a Unicode line separator, which a
/// YAML reader may take for a line break; one that is not plain and is part of a larger value, for which no
/// quoting is right.
fn written(
    name: &str,
    value: &str,
    place: Place,
    (before, after): (&str, &str),
) -> anyhow::Result<String> {
    ensure!(
        !value.contains(['\n', '\r']),
        "variable `{name}` spans several lines"
    );
    ensure!(
        !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')),
        "variable `{name}` has a control character"
    );
    let plain = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./:@+=%~#-".contains(c))
        && !value.starts_with(['#', '@', '%'])
        && !value.starts_with("---")
        && !value.starts_with("...")
        && !value.ends_with(':')
        && !matches!(value, "-" | "?");
    let null = matches!(value, "~" | "null" | "Null" | "NULL");
    let alone = match place {
        Place::Start { flow } => ends(after, flow),
        Place::Quoted(_) | Place::Other => false,
    };
    if plain && !(null && alone) {
        return Ok(value.to_owned());
    }
    match place {
        Place::Quoted(Quote::Single) if before.ends_with('\'') && after.starts_with('\'') => {
            return Ok(value.replace('\'', "''"));
        }
        Place::Quoted(Quote::Double) if before.ends_with('"') && after.starts_with('"') => {
            return Ok(value.replace('\\', "\\\\").replace('"', "\\\""));
        }
        _ => {}
    }
    ensure!(
        alone,
        "variable `{name}` is not alone as a value and holds text YAML could read as syntax: put `${{{name}}}` alone, or between quotes"
    );
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// Whether a scalar starting at a placeholder ends with it, `after` the rest of its line, `flow` inside a flow
/// collection or not: a mapping's key or value or an entry of a sequence or of a flow collection.
fn ends(after: &str, flow: bool) -> bool {
    let tail = after.trim_start();
    tail.is_empty()
        || (tail.len() < after.len() && tail.starts_with('#'))
        || (flow && tail.starts_with([',', ']', '}']))
        || tail
            .strip_prefix(':')
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
}

/// [`interpolate`] for one line, not a comment, appended to `out`, followed by `scan`.
fn interpolate_line(
    line: &str,
    env: impl Fn(&str) -> Option<String>,
    scan: &mut Scan,
    out: &mut String,
) -> anyhow::Result<()> {
    let mut rest = line;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        scan.feed(&rest[..at]);
        rest = &rest[at..];
        if let Some(after) = rest.strip_prefix("$$") {
            out.push('$');
            scan.feed("$");
            rest = after;
        } else if let Some(after) = rest.strip_prefix("${") {
            let end = after.find('}').context("a `${` is not closed by `}`")?;
            let (name, default) = match after[..end].split_once(":-") {
                Some((name, default)) => (name, Some(default)),
                None => (&after[..end], None),
            };
            ensure!(
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "`${{{}}}` does not name a variable",
                &after[..end]
            );
            let after = &after[end + 1..];
            match (env(name).filter(|value| !value.is_empty()), default) {
                (Some(value), _) => {
                    let before = &line[..line.len() - rest.len()];
                    out.push_str(&written(name, &value, scan.place(), (before, after))?);
                    scan.value();
                }
                (None, Some(default)) => {
                    out.push_str(default);
                    scan.feed(default);
                }
                (None, None) => bail!("variable `{name}` is not set"),
            }
            rest = after;
        } else {
            out.push('$');
            scan.feed("$");
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    scan.feed(rest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::tests::*;

    #[test]
    fn variables_are_replaced() {
        assert_eq!(interpolate("a ${PORT} b", env).unwrap(), "a 5353 b");
        assert_eq!(interpolate("${NOPE:-53}${EMPTY:-x}", env).unwrap(), "53x");
        assert_eq!(interpolate("$$ $PORT $", env).unwrap(), "$ $PORT $");
        // Comments are left as written, even with a variable unset or a `${` left open.
        let comments = "# ${NOPE}\n  # ${PORT\nport: ${PORT} # ${PORT}\n";
        assert_eq!(
            interpolate(comments, env).unwrap(),
            "# ${NOPE}\n  # ${PORT\nport: 5353 # 5353\n"
        );
    }

    #[test]
    fn variables_without_a_value_are_refused() {
        for (text, message) in [
            ("${NOPE}", "variable `NOPE` is not set"),
            ("${EMPTY}", "variable `EMPTY` is not set"),
            ("${LINES}", "variable `LINES` spans several lines"),
            ("${RETURN}", "variable `RETURN` spans several lines"),
            ("a: ${PORT\n}", "a `${` is not closed by `}`"),
            ("${PORT", "a `${` is not closed by `}`"),
            ("${}", "`${}` does not name a variable"),
            ("${A B}", "`${A B}` does not name a variable"),
        ] {
            let refused = interpolate(text, env).expect_err(text);
            assert_eq!(refused.to_string(), message);
        }
    }

    /// D115: a value YAML reads as null is the text all the same: `user: ${USER}` with `USER=null` must not read as
    /// no `user` (no privilege drop).
    #[test]
    fn a_value_that_reads_as_null_is_text() {
        for value in ["~", "null", "Null", "NULL"] {
            let env = |_: &str| Some(value.to_owned());
            for template in ["k: ${V}\n", "k: [${V}]\n", "{k: ${V}}\n", "- ${V}\n"] {
                let text = interpolate(template, env).unwrap();
                let read = if template.starts_with('-') {
                    serde_saphyr::from_str::<Vec<Option<String>>>(&text)
                        .map(|mut v| v.pop().flatten())
                } else if template.contains('[') {
                    serde_saphyr::from_str::<BTreeMap<String, Vec<Option<String>>>>(&text)
                        .map(|mut map| map.remove("k").and_then(|mut v| v.pop()).flatten())
                } else {
                    serde_saphyr::from_str::<BTreeMap<String, Option<String>>>(&text)
                        .map(|mut map| map.remove("k").flatten())
                };
                assert_eq!(read.unwrap().as_deref(), Some(value), "{text}");
            }
            // Within a larger value, it is text already.
            assert_eq!(
                interpolate("k: a${V}", env).unwrap(),
                format!("k: a{value}")
            );
        }
    }

    /// D115: a value is YAML text, not YAML: unless it is plain (letters, digits and `_./:@+=%~#-`), `${VAR}` must
    /// stand alone as a value, and is quoted there.
    #[test]
    fn a_variable_cannot_inject_yaml() {
        for (text, replaced) in [
            // Plain values go in as they are, in numbers, addresses and paths.
            ("port: ${PORT}", "port: 5353"),
            (
                "[${URL}, '${URL}']",
                "[tls://9.9.9.9#dns.quad9.net, 'tls://9.9.9.9#dns.quad9.net']",
            ),
            ("'a:${PORT}'", "'a:5353'"),
            // Anything else is quoted where it stands alone.
            ("key: ${TEXT}", "key: 'a: b #c'"),
            ("key: ${TEXT} # note", "key: 'a: b #c' # note"),
            (
                "servers: [${TEXT}, ${QUOTE}]",
                "servers: ['a: b #c', 'it''s']",
            ),
            ("{k: ${TEXT}}", "{k: 'a: b #c'}"),
            ("  - ${HASH}", "  - '#x'"),
            ("- - ${TEXT}", "- - 'a: b #c'"),
            ("${TEXT}: v", "'a: b #c': v"),
            ("${TEXT}", "'a: b #c'"),
            // Inside quotes, escaped for them.
            ("key: '${QUOTE}'", "key: 'it''s'"),
            (r#"key: "${QUOTE}""#, r#"key: "it's""#),
            (r#"key: "${DOUBLE}""#, r#"key: "say \"hi\"\\""#),
            (r"key: '${DOUBLE}'", r#"key: 'say "hi"\'"#),
            // By the quotes it is in, an escaped quote before it too.
            ("{k: 'a''${QUOTE}'}", "{k: 'a''it''s'}"),
            ("k: 'a b''${QUOTE}'", "k: 'a b''it''s'"),
            // A `#` after no space, and brackets within a plain scalar outside a flow, are text.
            ("[a#b, ${TEXT}]", "[a#b, 'a: b #c']"),
            ("k: a]b[c\n${TEXT}: v", "k: a]b[c\n'a: b #c': v"),
            ("k: [a]\nj: b\n${TEXT}: v", "k: [a]\nj: b\n'a: b #c': v"),
            // A value right after the `:` of a quoted key in a flow.
            (r#"{"a":${TEXT}}"#, r#"{"a":'a: b #c'}"#),
            // A `#` right after a value is text; a block scalar's text opens no flow.
            ("[a ${PORT}#b, ${TEXT}]", "[a 5353#b, 'a: b #c']"),
            ("k: |\n  [a\n${TEXT}: v", "k: |\n  [a\n'a: b #c': v"),
            // A `|` within a scalar starts no block scalar.
            ("[a|,\n  ${TEXT}]", "[a|,\n  'a: b #c']"),
            // After quotes closed, an escaped quote in them too.
            (r#"k: ["a\"", ${TEXT}]"#, r#"k: ["a\"", 'a: b #c']"#),
            (r#"k: "a\"${DOUBLE}""#, r#"k: "a\"say \"hi\"\\""#),
            ("k: 'a\n  '' ${PORT}'", "k: 'a\n  '' 5353'"),
            // After a tag, alone.
            ("key: !!str ${TEXT}", "key: !!str 'a: b #c'"),
            // Past a plain scalar or a block scalar, at the indentation of its key.
            ("- a\n- ${TEXT}", "- a\n- 'a: b #c'"),
            // Below a key whose line ends in a comment, the value.
            ("k: # ${PORT}\n  ${TEXT}", "k: # 5353\n  'a: b #c'"),
            ("k: |\n  t\nj: ${TEXT}", "k: |\n  t\nj: 'a: b #c'"),
            // A default is the template's own text.
            ("key: ${NOPE:-a: b}", "key: a: b"),
        ] {
            assert_eq!(interpolate(text, env).unwrap(), replaced, "{text}");
        }
        for text in [
            "key: x${TEXT}",
            "key: ${TEXT}x",
            "key: 'x ${TEXT}'",
            "key: ${TEXT}${PORT}",
            "key: ${PORT}${TEXT}",
            "key: 1 ${TEXT}",
            "key: a&b ${TEXT}",
            "[a:${TEXT}]",
            r#""a":${TEXT}"#,
            r#"["a"b:${TEXT}]"#,
            "key: ${QUOTE}'",
            r#"key: "${TEXT}"#,
            "key:${TEXT}",
            "a,${TEXT}",
            "[x ${TEXT}]",
            "x ${TEXT}",
            "-${TEXT}",
            "-- ${TEXT}",
            "k: -- ${TEXT}",
            "- -- ${TEXT}",
            "key: ${TEXT}#x",
            "key: ${TEXT} x",
            "key: ${TEXT},",
            // Inside quotes the line's brackets do not count, nor quotes of the other kind.
            r#"{k: "[${TEXT}]"}"#,
            r#"{k: 'a"${TEXT}"b'}"#,
            // A quote within a plain scalar opens nothing, on its line or the next.
            "k: a '${TEXT}'",
            "[a', ${TEXT}]",
            // A comment.
            "[a # , ${TEXT}]",
            "k: a\n  '${TEXT}'",
            "- a\n\n  '${TEXT}'",
            "[a\n '${QUOTE}']",
            "[a\n'${QUOTE}']",
            "k: a\n  b\n  '${TEXT}'",
            // The text of a block scalar.
            "k: |\n  ${TEXT}",
            "k: |\n  t\n  ${TEXT}",
            "k: |2-\n  a: ${TEXT}",
            // Text by its indentation, more than the key's, not by the length of the line.
            "  a_long_key: |\n    ${TEXT}",
            "k: >-\n  '${QUOTE}'",
        ] {
            let refused = interpolate(text, env).expect_err(text).to_string();
            assert!(refused.contains("not alone"), "{text}: {refused}");
        }
        for name in ["TAB", "NEL", "SEPARATOR"] {
            let refused = interpolate(&format!("k: ${{{name}}}"), env).unwrap_err();
            assert!(
                refused.to_string().contains("a control character"),
                "{name}: {refused}"
            );
        }
        // The injection this stops: two servers from one variable.
        let injected = MINIMAL.replace("'192.0.2.1'", "${TEXT}");
        assert!(error(&injected).contains("a: b #c"), "{}", error(&injected));
    }

    /// D115: whatever the value, `key: ${VAR}` and its quoted and flow forms read as the mapping `key` to exactly
    /// that text, or are refused: every text of up to three characters from those YAML gives a meaning to. Within
    /// a quoted text, a quote of the other kind, a bracket or a line break before it change nothing.
    #[test]
    fn a_value_is_the_text_it_stands_for() {
        const ALPHABET: [char; 17] = [
            'a', '\'', '"', '\\', '#', ' ', ':', '-', ',', '[', ']', '{', '}', '!', '&', '*', '?',
        ];
        let mut values = vec![String::new()];
        let mut start = 0;
        for _ in 0..3 {
            let end = values.len();
            for at in start..end {
                for c in ALPHABET {
                    values.push(format!("{}{c}", values[at]));
                }
            }
            start = end;
        }
        let mut read = 0;
        for value in values.iter().filter(|value| !value.is_empty()) {
            let env = |_: &str| Some(value.clone());
            for (template, flow, (prefix, suffix)) in [
                ("k: ${V}\n", false, ("", "")),
                ("k: '${V}'\n", false, ("", "")),
                ("k: \"${V}\"\n", false, ("", "")),
                ("k: [${V}]\n", true, ("", "")),
                ("{k: ${V}}\n", false, ("", "")),
                ("{k: 'a\"${V}\"b'}\n", false, ("a\"", "\"b")),
                ("k: \"a'${V}'b\"\n", false, ("a'", "'b")),
                ("{k: \"[${V}]\"}\n", false, ("[", "]")),
                ("k: '{${V}}'\n", false, ("{", "}")),
                ("k: \"a\n  ${V}\"\n", false, ("a ", "")),
                ("k: 'a\n  ${V}'\n", false, ("a ", "")),
            ] {
                let Ok(text) = interpolate(template, env) else {
                    continue;
                };
                let parsed = if flow {
                    serde_saphyr::from_str::<BTreeMap<String, Vec<String>>>(&text)
                        .map(|map| map.into_iter().map(|(k, v)| (k, v.concat())).collect())
                } else {
                    serde_saphyr::from_str::<BTreeMap<String, String>>(&text)
                };
                if let Ok(map) = parsed {
                    assert_eq!(
                        map,
                        BTreeMap::from([("k".to_owned(), format!("{prefix}{value}{suffix}"))]),
                        "{text}"
                    );
                    read += 1;
                }
            }
        }
        // Most of them read: the check is no refusal of everything.
        assert!(read > values.len(), "{read} of {}", values.len() * 11);
    }
}
