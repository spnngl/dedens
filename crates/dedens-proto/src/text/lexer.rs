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
    pub(crate) fn entry(&mut self, tokens: &mut Vec<Token<'t>>) -> Result<Option<bool>, TextError> {
        tokens.clear();
        while self.pos < self.text.len() {
            let blank = matches!(self.text.get(self.pos), Some(b' ' | b'\t'));
            self.read_entry(tokens)?;
            if !tokens.is_empty() {
                return Ok(Some(blank));
            }
        }
        Ok(None)
    }

    fn read_entry(&mut self, tokens: &mut Vec<Token<'t>>) -> Result<(), TextError> {
        let mut open = Vec::new();
        while let Some(&b) = self.text.get(self.pos) {
            match b {
                b' ' | b'\t' | b'\r' => self.pos += 1,
                b'\n' => {
                    self.pos += 1;
                    self.newline();
                    if open.is_empty() {
                        return Ok(());
                    }
                }
                b';' => {
                    while self.text.get(self.pos).is_some_and(|&b| b != b'\n') {
                        self.pos += 1;
                    }
                }
                b'(' => {
                    open.push(self.here());
                    self.pos += 1;
                }
                b')' => {
                    if open.pop().is_none() {
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
        match open.first() {
            Some(&(line, column)) => Err(TextError {
                line,
                column,
                kind: TextErrorKind::UnbalancedParenthesis,
            }),
            None => Ok(()),
        }
    }

    fn token(&mut self) -> Result<Token<'t>, TextError> {
        let start = self.pos;
        let (line, column) = self.here();
        let mut quoted = false;
        while let Some(&b) = self.text.get(self.pos) {
            match b {
                b'\\' => {
                    self.pos += 1;
                    if let Some(&next) = self.text.get(self.pos) {
                        self.pos += 1;
                        if next == b'\n' {
                            self.newline();
                        }
                    }
                }
                b'"' => {
                    quoted = !quoted;
                    self.pos += 1;
                }
                b'\n' if quoted => {
                    self.pos += 1;
                    self.newline();
                }
                b' ' | b'\t' | b'\r' | b'\n' | b';' | b'(' | b')' if !quoted => break,
                _ => self.pos += 1,
            }
        }
        if quoted {
            return Err(TextError {
                line,
                column,
                kind: TextErrorKind::UnterminatedQuote,
            });
        }
        Ok(Token {
            raw: self.text.get(start..self.pos).unwrap_or_default(),
            line,
            column,
        })
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
    }
}
