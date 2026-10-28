//! Unicode names (D18, D32): converted to A-labels by UTS 46 nontransitional processing, which IDNA2008 lookup
//! (RFC 5891 §5) takes after the mapping of RFC 5895; a label mixing scripts is flagged (IDN homographs), Chinese,
//! Japanese and Korean writing aside.

use unicode_script::{Script, ScriptExtension, UnicodeScript};

/// The name as asked: `text` itself when ASCII, else its A-labels, with a warning for each label mixing
/// scripts.
pub(crate) fn to_ascii(text: &str) -> Result<(String, Vec<String>), idna::Errors> {
    if text.is_ascii() {
        return Ok((text.to_owned(), Vec::new()));
    }
    let ascii = idna::domain_to_ascii(text)?;
    // The label separators of UTS 46 §2.3: full stop, ideographic, fullwidth and halfwidth ideographic.
    let warnings = text
        .split(['.', '\u{3002}', '\u{FF0E}', '\u{FF61}'])
        .filter_map(mixed_scripts)
        .collect();
    Ok((ascii, warnings))
}

/// The scripts written together, each set with Latin: Japanese, Korean and Chinese with Bopomofo (UTS 39 §5.2,
/// highly restrictive).
const TOGETHER: [&[Script]; 3] = [
    &[
        Script::Latin,
        Script::Han,
        Script::Hiragana,
        Script::Katakana,
    ],
    &[Script::Latin, Script::Han, Script::Hangul],
    &[Script::Latin, Script::Han, Script::Bopomofo],
];

/// A warning naming the scripts of `label` when no one script writes all its characters (UTS 39 §5.1), nor one
/// set of [`TOGETHER`].
fn mixed_scripts(label: &str) -> Option<String> {
    if !ScriptExtension::for_str(label).is_empty() {
        return None;
    }
    let mut scripts: Vec<Script> = Vec::new();
    for script in label.chars().map(|c| c.script()) {
        if !matches!(script, Script::Common | Script::Inherited) && !scripts.contains(&script) {
            scripts.push(script);
        }
    }
    if TOGETHER
        .iter()
        .any(|set| scripts.iter().all(|s| set.contains(s)))
    {
        return None;
    }
    let names: Vec<&str> = scripts.iter().map(|s| s.full_name()).collect();
    Some(format!("label {label} mixes scripts: {}", names.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_names_become_a_labels() {
        // RFC 3492 §7.1 (B): "Pročprostěnemluvíčesky" in Czech.
        let (ascii, warnings) = to_ascii("Pročprostěnemluvíčesky.example.").expect("valid");
        assert_eq!(ascii, "xn--proprostnemluvesky-uyb24dma41a.example.");
        assert_eq!(warnings, Vec::<String>::new());
        assert_eq!(
            to_ascii("_sip._tls.example").expect("ASCII").0,
            "_sip._tls.example"
        );
    }

    #[test]
    fn mixed_scripts_are_flagged() {
        // A Cyrillic "а" (U+0430) among Latin letters.
        let (ascii, warnings) = to_ascii("p\u{430}ypal.com").expect("valid");
        assert!(ascii.starts_with("xn--"), "{ascii}");
        assert_eq!(
            warnings,
            ["label p\u{430}ypal mixes scripts: Latin, Cyrillic"]
        );
    }

    #[test]
    fn japanese_korean_and_chinese_are_one_writing_each() {
        for name in [
            "日本語のドメイン.jp",
            "한국어中文.kr",
            "ㄅ中文.tw",
            "ドメインabc.jp",
        ] {
            assert_eq!(
                to_ascii(name).expect("valid").1,
                Vec::<String>::new(),
                "{name}"
            );
        }
        assert_eq!(
            to_ascii("한국어ひらがな.kr").expect("valid").1,
            ["label 한국어ひらがな mixes scripts: Hangul, Hiragana"]
        );
    }

    #[test]
    fn ideographic_full_stops_separate_labels() {
        let (ascii, warnings) = to_ascii("p\u{430}y\u{3002}例え.jp").expect("valid");
        assert_eq!(ascii.split('.').count(), 3, "{ascii}");
        assert_eq!(warnings, ["label p\u{430}y mixes scripts: Latin, Cyrillic"]);
    }
}
