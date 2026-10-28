//! Unicode names (D18, D32): converted to A-labels by UTS 46 nontransitional processing, which IDNA2008 lookup
//! (RFC 5891 §5) takes after the mapping of RFC 5895; a label mixing scripts is flagged (IDN homographs).

use unicode_script::{Script, ScriptExtension, UnicodeScript};

/// The name as asked: `text` itself when ASCII, else its A-labels, with a warning for each label mixing
/// scripts.
pub(crate) fn to_ascii(text: &str) -> Result<(String, Vec<String>), idna::Errors> {
    if text.is_ascii() {
        return Ok((text.to_owned(), Vec::new()));
    }
    let ascii = idna::domain_to_ascii(text)?;
    let warnings = text.split('.').filter_map(mixed_scripts).collect();
    Ok((ascii, warnings))
}

/// A warning naming the scripts of `label` when no one script writes all its characters (UTS 39 §5.1).
fn mixed_scripts(label: &str) -> Option<String> {
    if !ScriptExtension::for_str(label).is_empty() {
        return None;
    }
    let mut scripts: Vec<&str> = Vec::new();
    for script in label.chars().map(|c| c.script()) {
        if !matches!(script, Script::Common | Script::Inherited)
            && !scripts.contains(&script.full_name())
        {
            scripts.push(script.full_name());
        }
    }
    Some(format!(
        "label {label} mixes scripts: {}",
        scripts.join(", ")
    ))
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
}
