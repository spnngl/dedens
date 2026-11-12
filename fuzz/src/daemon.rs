//! The configuration file of `dedensd` (D24), reached through its library (D181).

/// Reads `data`, UTF-8, as a configuration file of `dedensd`, its `${VAR}` taken from [`env`]; one that names a file
/// to read is read but not built (`dedensd::read_config`). A refusal is fine; a panic is a bug.
///
/// # Panics
///
/// On a bug in the reader.
pub fn read_config(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = dedensd::read_config(text, env);
}

/// The environment: the variables of the example configuration (`apps/dedensd/src/config/mod.rs`), and a value of
/// each kind `${VAR}` treats apart, as its tests have them: plain, quoted, with YAML's comment, separators and line
/// breaks, empty.
fn env(name: &str) -> Option<String> {
    let value = match name {
        "COOKIE_SECRET" | "DIGITS" => "12345678901234567890123456789012",
        "OLD_COOKIE_SECRET" => "0123456789abcdef0123456789abcdef",
        "PORT" => "5353",
        "URL" => "tls://9.9.9.9#dns.quad9.net",
        "TEXT" => "a: b #c",
        "QUOTE" => "it's",
        "DOUBLE" => r#"say "hi"\"#,
        "HASH" => "#x",
        "TAB" => "a\tb",
        "NEL" => "a\u{85}b",
        "SEPARATOR" => "a\u{2028}b",
        "EMPTY" => "",
        "LINES" => "a\nb",
        "RETURN" => "a\rb: c",
        _ => return None,
    };
    Some(value.to_owned())
}
