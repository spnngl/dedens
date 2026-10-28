//! Splits zone-file text into entries of tokens (RFC 1035 §5.1).
//!
//! An entry ends at a line end outside parentheses. Blanks separate tokens, `;` starts a comment, `(` and `)`
//! let an entry span lines, a `"` opens or closes a quoted part in which blanks, `;`, parentheses and line ends
//! are text, and `\` takes the next byte as text. Tokens keep their quotes and escapes: what they mean depends on
//! the field (a `\.` is a dot inside a label, not a separator).

use super::{TextError, TextErrorKind};

/// Bytes that end a token or need a look: blanks, line ends, `;`, parentheses, `\`, `"` and `=`.
const SPECIAL: [bool; 256] = {
    let mut table = [false; 256];
    let bytes = b" \t\r\n;()\\\"=";
    let mut i = 0;
    while i < bytes.len() {
        table[bytes[i] as usize] = true;
        i += 1;
    }
    table
};

/// One item of an entry, as written, and where it starts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Token<'t> {
    pub(crate) raw: &'t [u8],
    pub(crate) line: usize,
    pub(crate) column: usize,
}

impl Token<'_> {
    /// An error about this token.
    pub(crate) const fn error(&self, kind: TextErrorKind) -> TextError {
        TextError {
            line: self.line,
            column: self.column,
            kind,
        }
    }
}

/// Reads a text entry by entry, and each entry token by token: the reader of the fields knows the record type,
/// which decides how a token is read (see [`Lexer::token`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lexer<'t> {
    text: &'t [u8],
    pos: usize,
    line: usize,
    line_start: usize,
    /// Where the `(` of the current entry is, while it is open.
    open: Option<(usize, usize)>,
    /// Whether the current entry may hold more tokens: its line end is not read yet.
    in_entry: bool,
    /// Line and column right after the last token read, where a missing field is reported.
    end: (usize, usize),
}

impl<'t> Lexer<'t> {
    pub(crate) const fn new(text: &'t [u8]) -> Self {
        Self {
            text,
            pos: 0,
            line: 1,
            line_start: 0,
            open: None,
            in_entry: false,
            end: (1, 1),
        }
    }

    /// Line and column right after the last token read.
    pub(crate) const fn end(&self) -> (usize, usize) {
        self.end
    }

    /// Moves to the next entry with at least one token, skipping what is left of the current one and blank and
    /// comment-only lines.
    ///
    /// Returns whether the entry starts with a blank, which leaves out the owner name, or `None` at the end of the
    /// text.
    ///
    /// # Errors
    ///
    /// [`TextError`] as [`Lexer::token`], or for an entry that starts with a parenthesis: its owner field would
    /// then not start the line (RFC 1035 §5.1).
    pub(crate) fn entry(&mut self) -> Result<Option<bool>, TextError> {
        while self.token(false)?.is_some() {}
        while self.pos < self.text.len() {
            let (line, column) = self.here();
            let first = self.text.get(self.pos).copied();
            self.in_entry = true;
            if self.skip()? {
                if first == Some(b'(') {
                    return Err(TextError {
                        line,
                        column,
                        kind: TextErrorKind::Invalid("entry: a parenthesis before the owner name"),
                    });
                }
                self.end = self.here();
                return Ok(Some(matches!(first, Some(b' ' | b'\t'))));
            }
        }
        Ok(None)
    }

    /// The next token of the current entry, or `None` at its end.
    ///
    /// A quoted part opens at the start of a token (RFC 1035 §5.1) or, with `pairs`, right after its first `=`:
    /// the `key="value"` of SVCB (RFC 9460 §2.1), the only type for which BIND reads such pairs. A quoted part ends
    /// the token; any other `"` is text.
    ///
    /// # Errors
    ///
    /// [`TextError`] for unbalanced or nested parentheses, an unterminated quote, or a `\` that ends a line
    /// outside quotes, which would join two entries.
    pub(crate) fn token(&mut self, pairs: bool) -> Result<Option<Token<'t>>, TextError> {
        if !self.in_entry || !self.skip()? {
            return Ok(None);
        }
        let start = self.pos;
        let (line, column) = self.here();
        // Whether a `"` at `pos` opens a quoted part.
        let mut quote_opens = true;
        let mut seen_equals = false;
        loop {
            if !quote_opens {
                // Plain text, most of a zone: no byte needs a decision.
                while self
                    .text
                    .get(self.pos)
                    .is_some_and(|&b| !SPECIAL[usize::from(b)])
                {
                    self.pos += 1;
                }
            }
            let Some(&b) = self.text.get(self.pos) else {
                break;
            };
            match b {
                b'\\' => {
                    if matches!(self.text.get(self.pos + 1), Some(b'\n' | b'\r')) {
                        return Err(self.error(TextErrorKind::Invalid(
                            "escape: a \\ that ends a line outside quotes",
                        )));
                    }
                    self.pos += 1;
                    self.escaped();
                }
                b'"' if quote_opens => {
                    self.pos += 1;
                    self.quoted(line, column)?;
                    break;
                }
                b' ' | b'\t' | b'\r' | b'\n' | b';' | b'(' | b')' => break,
                _ => self.pos += 1,
            }
            quote_opens = pairs && b == b'=' && !seen_equals;
            seen_equals |= b == b'=';
        }
        self.end = self.here();
        Ok(Some(Token {
            raw: self.text.get(start..self.pos).unwrap_or_default(),
            line,
            column,
        }))
    }

    /// Where the lexer is: line and column, from 1.
    const fn here(&self) -> (usize, usize) {
        (self.line, self.pos - self.line_start + 1)
    }

    /// Skips blanks, comments and parentheses up to the next token of the entry and returns `true`, or reads the
    /// end of the entry and returns `false`.
    fn skip(&mut self) -> Result<bool, TextError> {
        while let Some(&b) = self.text.get(self.pos) {
            match b {
                b' ' | b'\t' | b'\r' => self.pos += 1,
                b'\n' => {
                    self.pos += 1;
                    self.newline();
                    if self.open.is_none() {
                        self.in_entry = false;
                        return Ok(false);
                    }
                }
                b';' => {
                    while self.text.get(self.pos).is_some_and(|&b| b != b'\n') {
                        self.pos += 1;
                    }
                }
                b'(' => {
                    if self.open.is_some() {
                        return Err(self.error(TextErrorKind::Invalid("nested parenthesis")));
                    }
                    self.open = Some(self.here());
                    self.pos += 1;
                }
                b')' => {
                    if self.open.take().is_none() {
                        return Err(self.error(TextErrorKind::UnbalancedParenthesis));
                    }
                    self.pos += 1;
                }
                _ => return Ok(true),
            }
        }
        self.in_entry = false;
        match self.open.take() {
            Some((line, column)) => Err(TextError {
                line,
                column,
                kind: TextErrorKind::UnbalancedParenthesis,
            }),
            None => Ok(false),
        }
    }

    /// Reads up to and past the `"` closing a quoted part; `line` and `column` are where its token starts. A
    /// quoted part ends on its line unless the newline is escaped (D29), so a missing `"` cannot swallow the
    /// entries after it.
    fn quoted(&mut self, line: usize, column: usize) -> Result<(), TextError> {
        while let Some(&b) = self.text.get(self.pos) {
            self.pos += 1;
            match b {
                b'"' => return Ok(()),
                b'\\' => self.escaped(),
                b'\n' => break,
                _ => {}
            }
        }
        Err(TextError {
            line,
            column,
            kind: TextErrorKind::UnterminatedQuote,
        })
    }

    /// Takes the byte after a `\`, if any, as text.
    fn escaped(&mut self) {
        if let Some(&next) = self.text.get(self.pos) {
            self.pos += 1;
            if next == b'\n' {
                self.newline();
            }
        }
    }

    /// Notes that the byte before `pos` was a line end.
    const fn newline(&mut self) {
        self.line += 1;
        self.line_start = self.pos;
    }

    const fn error(&self, kind: TextErrorKind) -> TextError {
        let (line, column) = self.here();
        TextError { line, column, kind }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(text: &str, pairs: bool) -> Result<Vec<(bool, Vec<String>)>, TextError> {
        let mut lexer = Lexer::new(text.as_bytes());
        let mut out = Vec::new();
        while let Some(blank) = lexer.entry()? {
            let mut words = Vec::new();
            while let Some(t) = lexer.token(pairs)? {
                words.push(String::from_utf8_lossy(t.raw).into_owned());
            }
            out.push((blank, words));
        }
        Ok(out)
    }

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|&w| w.to_owned()).collect()
    }

    #[test]
    fn entries_end_at_line_ends_outside_parentheses() {
        let text = "a 1 IN SOA ( m r ; comment\n 1 2 )\n\n ; only a comment\n\tA 1.2.3.4\n";
        assert_eq!(
            entries(text, false).unwrap(),
            [
                (false, words(&["a", "1", "IN", "SOA", "m", "r", "1", "2"])),
                (true, words(&["A", "1.2.3.4"])),
            ]
        );
    }

    #[test]
    fn quotes_and_escapes_stay_in_the_token() {
        let text = "t TXT \"a b;(\\\nc\" x\\ y\r\n";
        assert_eq!(
            entries(text, false).unwrap(),
            [(false, words(&["t", "TXT", "\"a b;(\\\nc\"", "x\\ y"]))]
        );
    }

    #[test]
    fn quotes_open_at_the_start_or_with_pairs_after_the_first_equals() {
        let text = "a\"b c\"d \"q\"r k=\"v w\" k=v=\"x y\"";
        assert_eq!(
            entries(text, false).unwrap(),
            [(
                false,
                words(&[
                    "a\"b", "c\"d", "\"q\"", "r", "k=\"v", "w\"", "k=v=\"x", "y\""
                ])
            )]
        );
        assert_eq!(
            entries(text, true).unwrap(),
            [(
                false,
                words(&["a\"b", "c\"d", "\"q\"", "r", "k=\"v w\"", "k=v=\"x", "y\""])
            )]
        );
    }

    /// Without pairs, a quote after `=` cannot run into the next line and take its entry.
    #[test]
    fn a_quote_after_equals_stays_on_its_line() {
        assert_eq!(
            entries("x TXT a=\"b\ny TXT \"c\"\n", false).unwrap(),
            [
                (false, words(&["x", "TXT", "a=\"b"])),
                (false, words(&["y", "TXT", "\"c\""])),
            ]
        );
    }

    #[test]
    fn positions_count_lines_and_columns_from_one() {
        let mut lexer = Lexer::new(b"\n  a \"x\\\ny\" b\nc");
        let mut at = Vec::new();
        lexer.entry().unwrap();
        while let Some(t) = lexer.token(false).unwrap() {
            at.push((t.line, t.column));
        }
        assert_eq!(at, [(2, 3), (2, 5), (3, 4)]);
        lexer.entry().unwrap();
        let c = lexer.token(false).unwrap().unwrap();
        assert_eq!((c.line, c.column), (4, 1));
    }

    /// A missing field is reported after the last token, on the line where it ends.
    #[test]
    fn the_end_of_a_token_over_two_lines_is_on_the_second() {
        let mut lexer = Lexer::new(b"a \"x\\\nyz\"");
        lexer.entry().unwrap();
        while lexer.token(false).unwrap().is_some() {}
        assert_eq!(lexer.end(), (2, 4));
    }

    #[test]
    fn unbalanced_input_is_an_error() {
        let cases = [
            ("a ( b\n c", (1, 3, TextErrorKind::UnbalancedParenthesis)),
            ("a )", (1, 3, TextErrorKind::UnbalancedParenthesis)),
            ("a \"b\n", (1, 3, TextErrorKind::UnterminatedQuote)),
            // D29: the quote ends on its line; it would otherwise take the next entry.
            (
                "a \"b\nc TXT \"d\"",
                (1, 3, TextErrorKind::UnterminatedQuote),
            ),
            (
                "a ( b ( c ) )",
                (1, 7, TextErrorKind::Invalid("nested parenthesis")),
            ),
        ];
        for (text, want) in cases {
            let e = entries(text, false).unwrap_err();
            assert_eq!((e.line, e.column, e.kind), want, "{text:?}");
        }
    }

    #[test]
    fn an_entry_cannot_start_with_a_parenthesis() {
        let e = entries("; comment\n( a 60 A 192.0.2.1 )", false).unwrap_err();
        assert_eq!(
            (e.line, e.column, e.kind),
            (
                2,
                1,
                TextErrorKind::Invalid("entry: a parenthesis before the owner name")
            )
        );
    }

    /// A `\` before a line end would join two entries; inside quotes, the line end is text.
    #[test]
    fn an_escaped_line_end_outside_quotes_is_an_error() {
        for text in ["x TXT a\\\ny A 192.0.2.1\n", "x TXT a\\\r\n"] {
            let e = entries(text, false).unwrap_err();
            assert_eq!(
                (e.line, e.column, e.kind),
                (
                    1,
                    8,
                    TextErrorKind::Invalid("escape: a \\ that ends a line outside quotes")
                ),
                "{text:?}"
            );
        }
        assert_eq!(
            entries("x TXT \"a\\\nb\"", false).unwrap(),
            [(false, words(&["x", "TXT", "\"a\\\nb\""]))]
        );
    }
}
