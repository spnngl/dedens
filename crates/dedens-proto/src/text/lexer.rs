//! Splits zone-file text into entries of tokens (RFC 1035 §5.1).
//!
//! An entry ends at a line end outside parentheses. Blanks separate tokens, `;` starts a comment, `(` and `)`
//! let an entry span lines, a `"` opens or closes a quoted part in which blanks, `;`, parentheses and line ends
//! are text, and `\` takes the next byte as text. Tokens keep their quotes and escapes: what they mean depends on
//! the field (a `\.` is a dot inside a label, not a separator).

use super::{TextError, TextErrorKind};

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

/// Reads the entries of a text one after the other.
#[derive(Debug, Clone)]
pub(crate) struct Lexer<'t> {
    text: &'t [u8],
    pos: usize,
    line: usize,
    line_start: usize,
}

impl<'t> Lexer<'t> {
    pub(crate) const fn new(text: &'t [u8]) -> Self {
        Self {
            text,
            pos: 0,
            line: 1,
            line_start: 0,
        }
    }

    /// Where the lexer is: line and column, from 1.
    pub(crate) const fn here(&self) -> (usize, usize) {
        (self.line, self.pos - self.line_start + 1)
    }

    /// Reads the next entry with at least one token into `tokens`, skipping blank and comment-only lines.
    ///
    /// Returns whether the entry starts with a blank, which leaves out the owner name, or `None` at the end of the
    /// text.
    ///
    /// # Errors
    ///
    /// [`TextError`] for unbalanced or nested parentheses, an unterminated quote, or an entry that starts with a
    /// parenthesis: its owner field would then not start the line (RFC 1035 §5.1).
    pub(crate) fn entry(&mut self, tokens: &mut Vec<Token<'t>>) -> Result<Option<bool>, TextError> {
        tokens.clear();
        while self.pos < self.text.len() {
            let start = self.here();
            let first = self.text.get(self.pos).copied();
            self.read_entry(tokens)?;
            if !tokens.is_empty() {
                if first == Some(b'(') {
                    return Err(TextError {
                        line: start.0,
                        column: start.1,
                        kind: TextErrorKind::Invalid("entry: a parenthesis before the owner name"),
                    });
                }
                return Ok(Some(matches!(first, Some(b' ' | b'\t'))));
            }
        }
        Ok(None)
    }

    fn read_entry(&mut self, tokens: &mut Vec<Token<'t>>) -> Result<(), TextError> {
        let mut open = None;
        while let Some(&b) = self.text.get(self.pos) {
            match b {
                b' ' | b'\t' | b'\r' => self.pos += 1,
                b'\n' => {
                    self.pos += 1;
                    self.newline();
                    if open.is_none() {
                        return Ok(());
                    }
                }
                b';' => {
                    while self.text.get(self.pos).is_some_and(|&b| b != b'\n') {
                        self.pos += 1;
                    }
                }
                b'(' => {
                    if open.is_some() {
                        return Err(self.error(TextErrorKind::Invalid("nested parenthesis")));
                    }
                    open = Some(self.here());
                    self.pos += 1;
                }
                b')' => {
                    if open.take().is_none() {
                        return Err(self.error(TextErrorKind::UnbalancedParenthesis));
                    }
                    self.pos += 1;
                }
                _ => {
                    let token = self.token()?;
                    tokens.push(token);
                }
            }
        }
        match open {
            Some((line, column)) => Err(TextError {
                line,
                column,
                kind: TextErrorKind::UnbalancedParenthesis,
            }),
            None => Ok(()),
        }
    }

    /// Reads a token. A quoted part opens at its start (RFC 1035 §5.1), or right after its first `=` for the
    /// `key="value"` of SVCB (RFC 9460 §2.1, BIND's quoted-value pairs); it ends the token. Any other `"` is text.
    fn token(&mut self) -> Result<Token<'t>, TextError> {
        let start = self.pos;
        let (line, column) = self.here();
        let mut quote_opens = true;
        let mut seen_equals = false;
        while let Some(&b) = self.text.get(self.pos) {
            match b {
                b'\\' => {
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
            quote_opens = b == b'=' && !seen_equals;
            seen_equals |= b == b'=';
        }
        Ok(Token {
            raw: self.text.get(start..self.pos).unwrap_or_default(),
            line,
            column,
        })
    }

    /// Reads up to and past the `"` closing a quoted part; `line` and `column` are where its token starts.
    fn quoted(&mut self, line: usize, column: usize) -> Result<(), TextError> {
        while let Some(&b) = self.text.get(self.pos) {
            self.pos += 1;
            match b {
                b'"' => return Ok(()),
                b'\\' => self.escaped(),
                b'\n' => self.newline(),
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

    fn entries(text: &str) -> Result<Vec<(bool, Vec<String>)>, TextError> {
        let mut lexer = Lexer::new(text.as_bytes());
        let mut tokens = Vec::new();
        let mut out = Vec::new();
        while let Some(blank) = lexer.entry(&mut tokens)? {
            let words = tokens
                .iter()
                .map(|t| String::from_utf8_lossy(t.raw).into_owned())
                .collect();
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
            entries(text).unwrap(),
            [
                (false, words(&["a", "1", "IN", "SOA", "m", "r", "1", "2"])),
                (true, words(&["A", "1.2.3.4"])),
            ]
        );
    }

    #[test]
    fn quotes_and_escapes_stay_in_the_token() {
        let text = "t TXT \"a b;(\nc\" x\\ y key=\"q r\"\r\n";
        assert_eq!(
            entries(text).unwrap(),
            [(
                false,
                words(&["t", "TXT", "\"a b;(\nc\"", "x\\ y", "key=\"q r\""])
            )]
        );
    }

    #[test]
    fn quotes_open_at_the_start_or_after_the_first_equals_and_end_the_token() {
        let text = "a\"b c\"d \"q\"r k=\"v w\" k=v=\"x y\"";
        assert_eq!(
            entries(text).unwrap(),
            [(
                false,
                words(&["a\"b", "c\"d", "\"q\"", "r", "k=\"v w\"", "k=v=\"x", "y\""])
            )]
        );
    }

    #[test]
    fn positions_count_lines_and_columns_from_one() {
        let mut lexer = Lexer::new(b"\n  a \"x\ny\" b\nc");
        let mut tokens = Vec::new();
        lexer.entry(&mut tokens).unwrap();
        let at: Vec<_> = tokens.iter().map(|t| (t.line, t.column)).collect();
        assert_eq!(at, [(2, 3), (2, 5), (3, 4)]);
        lexer.entry(&mut tokens).unwrap();
        assert_eq!((tokens[0].line, tokens[0].column), (4, 1));
    }

    #[test]
    fn unbalanced_input_is_an_error() {
        let e = entries("a ( b\n c").unwrap_err();
        assert_eq!(
            (e.line, e.column, e.kind),
            (1, 3, TextErrorKind::UnbalancedParenthesis)
        );
        let e = entries("a )").unwrap_err();
        assert_eq!(
            (e.line, e.column, e.kind),
            (1, 3, TextErrorKind::UnbalancedParenthesis)
        );
        let e = entries("a \"b\n").unwrap_err();
        assert_eq!(
            (e.line, e.column, e.kind),
            (1, 3, TextErrorKind::UnterminatedQuote)
        );
        let e = entries("a ( b ( c ) )").unwrap_err();
        assert_eq!(
            (e.line, e.column, e.kind),
            (1, 7, TextErrorKind::Invalid("nested parenthesis"))
        );
    }

    #[test]
    fn an_entry_cannot_start_with_a_parenthesis() {
        let e = entries("; comment\n( a 60 A 192.0.2.1 )").unwrap_err();
        assert_eq!(
            (e.line, e.column, e.kind),
            (
                2,
                1,
                TextErrorKind::Invalid("entry: a parenthesis before the owner name")
            )
        );
    }
}
