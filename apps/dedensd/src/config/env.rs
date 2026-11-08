//! `${VAR}` in the configuration (D44, D115): each placeholder replaced by its variable's value as YAML text, never
//! as YAML.

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
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with('#') {
            out.push_str(line);
        } else {
            interpolate_line(line, &env, &mut out)?;
        }
    }
    Ok(out)
}

/// How the value of variable `name` is written where `${name}` stands between `before` and `after`, the rest of its
/// line in the template: a value cannot add YAML of its own (D44, D115).
/// - A plain value, made of letters, digits and `_./:@+=%~#-` that YAML cannot read as syntax (it does not start
///   with `#`, `@`, `%`, `---`, `...` or end with `:`, and is not `-` or `?`), is written as it is: ports,
///   addresses, paths and URLs stay usable anywhere, in a number or in a quoted text.
/// - Between quotes of the template, it is escaped for them.
/// - Alone as a value (a whole scalar: after `key:`, `-`, `,` or `[` in a flow, before a `,`, a `]`, a `}`, a
///   comment or the end of the line), it is written in single quotes.
///
/// # Errors
///
/// A value spanning lines (`\n` or `\r`), with another control character or a Unicode line separator, which a
/// YAML reader may take for a line break; one that is not plain and is part of a larger value, for which no
/// quoting is right.
fn written(name: &str, value: &str, before: &str, after: &str) -> anyhow::Result<String> {
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
    if plain {
        return Ok(value.to_owned());
    }
    if before.ends_with('\'') && after.starts_with('\'') {
        return Ok(value.replace('\'', "''"));
    }
    if before.ends_with('"') && after.starts_with('"') {
        return Ok(value.replace('\\', "\\\\").replace('"', "\\\""));
    }
    ensure!(
        alone(before, after),
        "variable `{name}` is not alone as a value and holds text YAML could read as syntax: put `${{{name}}}` alone, or between quotes"
    );
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// Whether a placeholder between `before` and `after` makes a whole YAML scalar, a mapping's key or value or an
/// entry of a sequence or of a flow collection. Reads the line of the template only: it is the template author's.
fn alone(before: &str, after: &str) -> bool {
    let flow = before.matches(['[', '{']).count() > before.matches([']', '}']).count();
    let head = before.trim_end();
    let spaced = head.len() < before.len();
    let starts = head.is_empty()
        || (flow && head.ends_with(['[', '{', ',']))
        || (spaced && head.ends_with(':'))
        || (spaced && head.chars().all(|c| c == '-' || c.is_whitespace()));
    let tail = after.trim_start();
    let ends = tail.is_empty()
        || (tail.len() < after.len() && tail.starts_with('#'))
        || (flow && tail.starts_with([',', ']', '}']))
        || tail
            .strip_prefix(':')
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace));
    starts && ends
}

/// [`interpolate`] for one line, not a comment, appended to `out`.
fn interpolate_line(
    line: &str,
    env: impl Fn(&str) -> Option<String>,
    out: &mut String,
) -> anyhow::Result<()> {
    let mut rest = line;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        if let Some(after) = rest.strip_prefix("$$") {
            out.push('$');
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
                    out.push_str(&written(name, &value, before, after)?);
                }
                (None, Some(default)) => out.push_str(default),
                (None, None) => bail!("variable `{name}` is not set"),
            }
            rest = after;
        } else {
            out.push('$');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
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
            ("${TEXT}: v", "'a: b #c': v"),
            ("${TEXT}", "'a: b #c'"),
            // Inside quotes, escaped for them.
            ("key: '${QUOTE}'", "key: 'it''s'"),
            (r#"key: "${QUOTE}""#, r#"key: "it's""#),
            (r#"key: "${DOUBLE}""#, r#"key: "say \"hi\"\\""#),
            (r"key: '${DOUBLE}'", r#"key: 'say "hi"\'"#),
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
            "key: ${QUOTE}'",
            r#"key: "${TEXT}"#,
            "key:${TEXT}",
            "a,${TEXT}",
            "[x ${TEXT}]",
            "x ${TEXT}",
            "-${TEXT}",
            "key: ${TEXT}#x",
            "key: ${TEXT} x",
            "key: ${TEXT},",
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
    /// that text, or are refused: every text of up to three characters from those YAML gives a meaning to.
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
            for (template, flow) in [
                ("k: ${V}\n", false),
                ("k: '${V}'\n", false),
                ("k: \"${V}\"\n", false),
                ("k: [${V}]\n", true),
                ("{k: ${V}}\n", false),
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
                        BTreeMap::from([("k".to_owned(), value.clone())]),
                        "{text}"
                    );
                    read += 1;
                }
            }
        }
        // Most of them read: the check is no refusal of everything.
        assert!(read > values.len(), "{read} of {}", values.len() * 5);
    }
}
