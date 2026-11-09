//! The repository checks (D140): facts the docs rely on, kept true by the gate. Each check is a function of text
//! (or of a closure for the file system), so a small broken input shows it failing; the tests of the tree feed it
//! the tracked files, read from the workspace root.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The decisions' folder, from the workspace root: a file per section, and the index (D171).
const DECISIONS: &str = "docs/decisions/";
/// The decisions' index, a line per decision.
const INDEX: &str = "docs/decisions/README.md";
/// The RFC coverage table, from the workspace root.
const COVERAGE: &str = "docs/rfc/coverage.md";
/// Extensions of the text files that cite decisions, anywhere in the tree; a file with none (`justfile`,
/// `Containerfile`) does too. RFC archives (`.txt`) and captured data are not read.
const CITING_EXTENSIONS: [&str; 10] = [
    "rs", "md", "toml", "yaml", "yml", "sh", "go", "c", "py", "nu",
];
/// The folder whose files all cite decisions, whatever their extension: man pages, systemd units, package scripts.
const CITING_FOLDER: &str = "deploy/";
/// Where a path of a coverage cell starts.
const PATH_ROOTS: [&str; 6] = ["crates/", "apps/", "fuzz/", "tests/", "docs/", "testdata/"];

// --- Inputs ---

/// A tracked file: its path from the workspace root and its text.
struct Source {
    path: String,
    text: String,
}

impl Source {
    fn new(path: &str, text: &str) -> Self {
        Self {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    /// The lines with their numbers from 1.
    fn lines(&self) -> impl Iterator<Item = (usize, &str)> {
        self.text.lines().enumerate().map(|(i, line)| (i + 1, line))
    }

    /// A failure as `path:line: message`.
    fn problem(&self, line: usize, message: &str) -> String {
        format!("{}:{line}: {message}", self.path)
    }
}

/// The workspace root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The paths git tracks, from the workspace root: `plan/`, `target/` and the rest of `.gitignore` are out.
fn tracked() -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root())
        .output()
        .expect("git runs");
    assert!(output.status.success(), "git ls-files failed");
    String::from_utf8(output.stdout)
        .expect("paths are UTF-8")
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect()
}

fn read(path: &str) -> Source {
    let text = fs::read_to_string(root().join(path)).expect("tracked file reads");
    Source::new(path, &text)
}

/// Whether a tracked path is a section file of the decisions: a file of `DECISIONS`, but the index.
fn is_section(path: &str) -> bool {
    path.starts_with(DECISIONS)
        && Path::new(path).extension() == Some(OsStr::new("md"))
        && path != INDEX
}

/// The section files of the decisions.
fn sections(tracked: &[String]) -> Vec<Source> {
    tracked
        .iter()
        .filter(|path| is_section(path))
        .map(|path| read(path))
        .collect()
}

/// The tracked files that may cite a decision, but the section files, which define them. A symlink (`CLAUDE.md`) is
/// its target's copy.
fn citing(tracked: &[String]) -> Vec<Source> {
    let wanted = |path: &str| {
        path.starts_with(CITING_FOLDER)
            || Path::new(path).extension().is_none_or(|extension| {
                extension
                    .to_str()
                    .is_some_and(|extension| CITING_EXTENSIONS.contains(&extension))
            })
    };
    tracked
        .iter()
        .filter(|path| !is_section(path) && wanted(path))
        .filter(|path| {
            fs::symlink_metadata(root().join(path)).is_ok_and(|meta| !meta.file_type().is_symlink())
        })
        .map(|path| read(path))
        .collect()
}

/// Fails with every problem, one a line.
fn report(problems: &[String]) {
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

// --- Decision ids ---

/// A decision id found in a text: `D14`, `D7a`.
struct Id {
    number: u32,
    letter: Option<char>,
    /// The byte after it.
    end: usize,
}

impl Id {
    fn name(number: u32, letter: Option<char>) -> String {
        format!("D{number}{}", letter.into_iter().collect::<String>())
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The id starting at byte `at` of `text`: `D`, digits, a lowercase letter perhaps, and no word character
/// before or after (`0xD4`, `D4D` are not ids).
fn id_at(text: &str, at: usize) -> Option<Id> {
    if !text[at..].starts_with('D') || text[..at].chars().next_back().is_some_and(is_word) {
        return None;
    }
    let digits = at + 1;
    let digits_end = digits
        + text[digits..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
    let number = text[digits..digits_end].parse().ok()?;
    let letter = text[digits_end..]
        .chars()
        .next()
        .filter(char::is_ascii_lowercase);
    let end = digits_end + letter.map_or(0, char::len_utf8);
    if text[end..].chars().next().is_some_and(is_word) {
        return None;
    }
    Some(Id {
        number,
        letter,
        end,
    })
}

/// Every decision `text` cites, in order, a range such as `D64-D66` (or with an en dash) expanded.
fn cited(text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut at = 0;
    while let Some(c) = text[at..].chars().next() {
        let Some(first) = id_at(text, at) else {
            at += c.len_utf8();
            continue;
        };
        at = first.end;
        let last = text[first.end..]
            .strip_prefix(['-', '\u{2013}'])
            .and_then(|_| {
                id_at(
                    text,
                    first.end + text[first.end..].chars().next()?.len_utf8(),
                )
            })
            .filter(|last| {
                first.letter.is_none() && last.letter.is_none() && first.number <= last.number
            });
        match last {
            Some(last) => {
                ids.extend((first.number..=last.number).map(|n| Id::name(n, None)));
                at = last.end;
            }
            None => ids.push(Id::name(first.number, first.letter)),
        }
    }
    ids
}

// --- Decisions: defined once, cited ones exist ---

/// A decision's entry in a section file: a line starting `- D`, and the indented lines after it.
struct Definition {
    id: String,
    /// The section file.
    path: String,
    line: usize,
    /// The entry on one line, after the id.
    text: String,
}

impl Definition {
    /// A failure as `path:line: message`.
    fn problem(&self, message: &str) -> String {
        format!("{}:{}: {message}", self.path, self.line)
    }

    /// What the header says, `amends D2; amended by D5`: the parenthesis right after the id.
    fn header(&self) -> Option<&str> {
        let inner = self.text.strip_prefix(" (")?;
        Some(inner.split_once(')')?.0)
    }
}

/// The definitions of every section file, file by file, each in its order.
fn definitions(sections: &[Source]) -> Vec<Definition> {
    let mut found: Vec<Definition> = Vec::new();
    for section in sections {
        let first = found.len();
        for (line, text) in section.lines() {
            let start = text.strip_prefix("- ").and_then(|_| id_at(text, 2));
            match (start, found[first..].last_mut()) {
                (Some(id), _) => found.push(Definition {
                    id: Id::name(id.number, id.letter),
                    path: section.path.clone(),
                    line,
                    text: text[id.end..].to_owned(),
                }),
                (None, Some(open)) if text.starts_with(' ') => {
                    open.text.push(' ');
                    open.text.push_str(text.trim());
                }
                (None, _) => {}
            }
        }
    }
    found
}

/// A decision defined twice, a decision cited (in `sections` or in `others`) and defined nowhere.
fn undefined_or_duplicated(sections: &[Source], others: &[Source]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut defined: BTreeMap<String, String> = BTreeMap::new();
    for definition in definitions(sections) {
        if let Some(first) = defined.get(&definition.id) {
            problems.push(definition.problem(&format!(
                "{} is defined twice, first at {first}",
                definition.id
            )));
        } else {
            let at = format!("{}:{}", definition.path, definition.line);
            defined.insert(definition.id, at);
        }
    }
    for source in sections.iter().chain(others) {
        for (line, text) in source.lines() {
            problems.extend(
                cited(text)
                    .into_iter()
                    .filter(|id| !defined.contains_key(id))
                    .map(|id| source.problem(line, &format!("{id} is not defined in {DECISIONS}"))),
            );
        }
    }
    problems
}

// --- Decisions: relations agree ---

/// What a decision's header says about another decision.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Relation {
    Amends,
    AmendedBy,
    Supersedes,
    SupersededBy,
    Narrows,
    NarrowedBy,
    /// One-sided: the other decision does not name it.
    BuildsOn,
    /// One-sided, as `BuildsOn`.
    Completes,
}

impl Relation {
    const ALL: [Self; 8] = [
        Self::Amends,
        Self::AmendedBy,
        Self::Supersedes,
        Self::SupersededBy,
        Self::Narrows,
        Self::NarrowedBy,
        Self::BuildsOn,
        Self::Completes,
    ];

    /// The words of the header.
    fn phrase(self) -> &'static str {
        match self {
            Self::Amends => "amends",
            Self::AmendedBy => "amended by",
            Self::Supersedes => "supersedes",
            Self::SupersededBy => "superseded by",
            Self::Narrows => "narrows",
            Self::NarrowedBy => "narrowed by",
            Self::BuildsOn => "builds on",
            Self::Completes => "completes",
        }
    }

    /// What the other decision must say back; none for the one-sided relations.
    fn counterpart(self) -> Option<Self> {
        match self {
            Self::Amends => Some(Self::AmendedBy),
            Self::AmendedBy => Some(Self::Amends),
            Self::Supersedes => Some(Self::SupersededBy),
            Self::SupersededBy => Some(Self::Supersedes),
            Self::Narrows => Some(Self::NarrowedBy),
            Self::NarrowedBy => Some(Self::Narrows),
            Self::BuildsOn | Self::Completes => None,
        }
    }

    /// Whether later decisions write it into the header of the one they change: the index repeats these.
    fn is_status(self) -> bool {
        matches!(
            self,
            Self::AmendedBy | Self::SupersededBy | Self::NarrowedBy
        )
    }
}

/// A decision's relations to others, from its header.
struct Entry {
    id: String,
    /// Where it is defined, `path:line`.
    at: String,
    relations: BTreeSet<(Relation, String)>,
}

/// What the header of a definition says, `(amends D2; amended by D5, D6)`: its relations, and the clauses that
/// name decisions in no known form (`(amend D2)` would otherwise pass for no relation).
fn relations(definition: &Definition) -> (Entry, Vec<String>) {
    let mut entry = Entry {
        id: definition.id.clone(),
        at: format!("{}:{}", definition.path, definition.line),
        relations: BTreeSet::new(),
    };
    let mut unknown = Vec::new();
    let Some(header) = definition.header() else {
        return (entry, unknown);
    };
    for clause in header.split(';').map(str::trim) {
        let known = Relation::ALL.into_iter().find_map(|relation| {
            let rest = clause.strip_prefix(relation.phrase())?;
            Some((relation, rest.strip_prefix(' ')?))
        });
        match known {
            Some((relation, rest)) => {
                let ids = cited(rest);
                entry.relations.extend(ids.into_iter().map(|id| (relation, id)));
            }
            None if !cited(clause).is_empty() => unknown.push(definition.problem(&format!(
                "the header clause {clause:?} of {} has no known relation (amends, amended by, supersedes, \
                 superseded by, narrows, narrowed by, builds on, completes)",
                definition.id
            ))),
            None => {}
        }
    }
    (entry, unknown)
}

/// A decision that amends, supersedes or narrows another which does not say so back, and the reverse. A
/// supersession limited to a scope (`superseded by D113 for UDP`) is one still: the two sides name each other.
fn unpaired(sections: &[Source]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    for definition in definitions(sections) {
        let (entry, unknown) = relations(&definition);
        problems.extend(unknown);
        if !entries.iter().any(|seen| seen.id == entry.id) {
            entries.push(entry);
        }
    }
    let by_id: BTreeMap<&str, &Entry> = entries.iter().map(|e| (e.id.as_str(), e)).collect();
    for entry in &entries {
        for (relation, other) in &entry.relations {
            let (Some(back), Some(other_entry)) =
                (relation.counterpart(), by_id.get(other.as_str()))
            else {
                continue;
            };
            if !other_entry.relations.contains(&(back, entry.id.clone())) {
                problems.push(format!(
                    "{}: {} {} {other}, but {other} ({}) does not say \"{} {}\"",
                    entry.at,
                    entry.id,
                    relation.phrase(),
                    other_entry.at,
                    back.phrase(),
                    entry.id
                ));
            }
        }
    }
    problems
}

// --- Decisions: the index ---

/// The clauses of a header the index repeats, `amended by D5; superseded by D7` (`Relation::is_status`), in the
/// header's order; empty for none.
fn status(definition: &Definition) -> String {
    let clauses = definition.header().into_iter().flat_map(|header| {
        header.split(';').map(str::trim).filter(|clause| {
            Relation::ALL.into_iter().any(|relation| {
                relation.is_status()
                    && clause
                        .strip_prefix(relation.phrase())
                        .is_some_and(|rest| rest.starts_with(' '))
            })
        })
    });
    clauses.collect::<Vec<_>>().join("; ")
}

/// The index out of step with the sections. A line, `- D12 [section](file.md) (amended by D159): gist`, follows
/// the one before in number order, names a decision and the section file defining it, and has in parentheses its
/// header's status clauses (`status`), none when the header has none. A decision with no line fails too.
fn index_differs(index: &Source, sections: &[Source]) -> Vec<String> {
    let definitions = definitions(sections);
    let mut problems = Vec::new();
    let mut listed = BTreeSet::new();
    let mut previous = None;
    for (line, text) in index.lines() {
        let Some(id) = text.strip_prefix("- ").and_then(|_| id_at(text, 2)) else {
            continue;
        };
        let name = Id::name(id.number, id.letter);
        let key = (id.number, id.letter);
        if previous.is_some_and(|previous| previous >= key) {
            problems.push(index.problem(line, &format!("{name} is out of number order")));
        }
        previous = Some(key);
        let Some(definition) = definitions.iter().find(|definition| definition.id == name) else {
            problems.push(index.problem(line, &format!("{name} is not defined in {DECISIONS}")));
            continue;
        };
        listed.insert(name.clone());
        let link = text[id.end..]
            .strip_prefix(" [")
            .and_then(|rest| rest.split_once("]("))
            .and_then(|(_, rest)| rest.split_once(')'));
        let Some((file, rest)) = link else {
            problems.push(index.problem(line, &format!("{name} has no [section](file.md) link")));
            continue;
        };
        if format!("{DECISIONS}{file}") != definition.path {
            problems.push(index.problem(
                line,
                &format!("{name} links {file}, but {} defines it", definition.path),
            ));
        }
        let said = rest
            .strip_prefix(" (")
            .and_then(|rest| rest.split_once(')'))
            .map_or("", |(said, _)| said);
        let status = status(definition);
        if said != status {
            problems.push(index.problem(
                line,
                &format!("{name} says ({said}), its header ({status})"),
            ));
        }
    }
    problems.extend(
        definitions
            .iter()
            .filter(|definition| !listed.contains(&definition.id))
            .map(|definition| {
                definition.problem(&format!("{} has no line in {INDEX}", definition.id))
            }),
    );
    problems
}

// --- Coverage: paths exist, each RFC test file has its row ---

/// The data rows of the table: line number and cells, the empty ones around the outer bars included.
fn rows(coverage: &Source) -> impl Iterator<Item = (usize, Vec<&str>)> {
    coverage
        .lines()
        .filter(|(_, line)| line.starts_with("| ["))
        .map(|(line, text)| (line, text.split('|').collect()))
}

/// The alternatives of a pattern with braces, nested ones too: `a/{b,c/{d,e}}.rs` is `a/b.rs`, `a/c/d.rs`,
/// `a/c/e.rs`. Unbalanced braces leave the pattern as it is.
fn expand(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_owned()];
    };
    let mut depth = 0_usize;
    let mut cuts = vec![open];
    for (i, c) in pattern[open..].char_indices() {
        let at = open + i;
        match c {
            '{' => depth += 1,
            ',' if depth == 1 => cuts.push(at),
            '}' => {
                depth -= 1;
                if depth == 0 {
                    cuts.push(at);
                    let (head, tail) = (&pattern[..open], &pattern[at + 1..]);
                    return cuts
                        .windows(2)
                        .flat_map(|cut| {
                            expand(&format!("{head}{}{tail}", &pattern[cut[0] + 1..cut[1]]))
                        })
                        .collect();
                }
            }
            _ => {}
        }
    }
    vec![pattern.to_owned()]
}

/// Whether `name` matches `pattern`, whose `*` stands for any run of characters.
fn matches_glob(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, tail)) => name.strip_prefix(head).is_some_and(|rest| {
            (0..=rest.len())
                .filter(|&i| rest.is_char_boundary(i))
                .any(|i| matches_glob(tail, &rest[i..]))
        }),
    }
}

/// Whether `path` (a `*` allowed in its last component) exists under the workspace root.
fn exists_on_disk(path: &str) -> bool {
    let full = root().join(path);
    let Some(name) = full.file_name().and_then(OsStr::to_str) else {
        return full.exists();
    };
    if !name.contains('*') {
        return full.exists();
    }
    let Some(parent) = full.parent() else {
        return false;
    };
    fs::read_dir(parent).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|n| matches_glob(name, n))
        })
    })
}

/// A row of the wrong width, a path in a Code or Tests cell (a backticked span starting with one of the
/// `PATH_ROOTS`, braces and a `*` allowed) that `exists` does not find.
fn missing_paths(coverage: &Source, exists: impl Fn(&str) -> bool) -> Vec<String> {
    let mut problems = Vec::new();
    for (line, cells) in rows(coverage) {
        let [_, _, _, _, code, tests, _] = cells.as_slice() else {
            problems.push(coverage.problem(
                line,
                &format!("the row has {} cells, not 5", cells.len() - 2),
            ));
            continue;
        };
        for cell in [code, tests] {
            let spans = cell.split('`').skip(1).step_by(2);
            for span in spans.filter(|s| PATH_ROOTS.iter().any(|root| s.starts_with(root))) {
                problems.extend(
                    expand(span)
                        .into_iter()
                        .filter(|path| !exists(path))
                        .map(|path| coverage.problem(line, &format!("{path} does not exist"))),
                );
            }
        }
    }
    problems
}

/// Whether `path` is a Rust file under a `tests/` folder of a crate or an app, at any depth.
fn is_test_file(path: &str) -> bool {
    let file = Path::new(path);
    let owned = path.starts_with("crates/") || path.starts_with("apps/");
    let in_tests = file
        .ancestors()
        .skip(1)
        .any(|folder| folder.file_name() == Some(OsStr::new("tests")));
    owned && in_tests && file.extension() == Some(OsStr::new("rs"))
}

/// The RFC numbers a text cites as `RFC NNNN` or `RFCs NNNN, NNNN and NNNN`, in order, repeats included.
fn rfcs_cited(text: &str) -> impl Iterator<Item = &str> {
    let mut cited = Vec::new();
    for (at, cue) in text.match_indices("RFC") {
        let after = &text[at + cue.len()..];
        let (mut rest, plural) = match (after.strip_prefix("s "), after.strip_prefix(' ')) {
            (Some(rest), _) => (rest, true),
            (None, Some(rest)) => (rest, false),
            (None, None) => continue,
        };
        loop {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                break;
            }
            cited.push(&rest[..digits]);
            rest = &rest[digits..];
            let next = [", and ", " and ", ", "]
                .iter()
                .find_map(|separator| rest.strip_prefix(separator));
            match next {
                Some(next) if plural => rest = next,
                _ => break,
            }
        }
    }
    cited.into_iter()
}

/// An RFC that a test file (`is_test_file`, holding a `#[test]` or a `#[...::test]` of a runtime) cites in its module docs (`//!` lines, `RFC NNNN`)
/// whose row in the table is missing, or does not name the file in its Tests cell (a path, braces and a `*`
/// allowed). Test files group by topic, not by RFC, so the docs are where a file says which RFCs it tests; a file of
/// helpers alone tests none.
fn missing_rows(coverage: &Source, files: &[Source]) -> Vec<String> {
    let named: BTreeMap<&str, Vec<String>> = rows(coverage)
        .filter_map(|(_, cells)| {
            let [_, rfc, _, _, _, tests, _] = cells.as_slice() else {
                return None;
            };
            let rest = rfc.split("rfc").nth(1)?;
            let number = &rest[..rest.bytes().take_while(u8::is_ascii_digit).count()];
            let paths = tests.split('`').skip(1).step_by(2).flat_map(expand);
            Some((number, paths.collect()))
        })
        .collect();
    let mut problems = Vec::new();
    let tests = files
        .iter()
        .filter(|file| is_test_file(&file.path))
        .filter(|file| {
            ["#[test]", "::test]"]
                .iter()
                .any(|mark| file.text.contains(mark))
        });
    for file in tests {
        let doc: Vec<&str> = file
            .text
            .lines()
            .filter_map(|line| Some(line.trim_start().strip_prefix("//!")?.trim()))
            .collect();
        let doc = doc.join(" ");
        let cited: BTreeSet<&str> = rfcs_cited(&doc).collect();
        for number in cited {
            let problem = match named.get(number) {
                None => "has no row",
                Some(paths) if !paths.iter().any(|p| matches_glob(p, &file.path)) => {
                    "has a row that does not name it"
                }
                Some(_) => continue,
            };
            problems.push(format!(
                "{}: RFC {number} {problem} in {COVERAGE}",
                file.path
            ));
        }
    }
    problems
}

// --- AGENTS.md beside its CLAUDE.md ---

/// An `AGENTS.md` with no `CLAUDE.md` beside it that is a symlink to it. `link` gives the target of the symlink
/// at a path, none when it is not one.
fn missing_links(tracked: &[String], link: impl Fn(&str) -> Option<PathBuf>) -> Vec<String> {
    tracked
        .iter()
        .filter(|path| Path::new(path).file_name() == Some(OsStr::new("AGENTS.md")))
        .filter_map(|agents| {
            let claude = Path::new(agents).with_file_name("CLAUDE.md");
            let claude = claude.to_str()?;
            match link(claude) {
                None => Some(format!("{agents}: no {claude} symlink beside it")),
                Some(target) if target != Path::new("AGENTS.md") => Some(format!(
                    "{claude}: links to {}, not to AGENTS.md",
                    target.display()
                )),
                Some(_) => None,
            }
        })
        .collect()
}

// --- The release image's Rust ---

/// The Containerfile's Rust, when it is not `channel`, the one `rust-toolchain.toml` pins (D153): the image's own
/// toolchain builds the release, so a tag of another version builds with a Rust the gate never ran.
fn image_rust_differs(containerfile: &str, toolchain: &str) -> Vec<String> {
    let channel = toolchain
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = \"")?.strip_suffix('"'))
        .expect("rust-toolchain.toml pins a channel");
    let from = containerfile
        .lines()
        .find_map(|line| line.strip_prefix("FROM docker.io/library/rust:"))
        .expect("the Containerfile builds FROM rust");
    let tag = from.split(['@', ' ']).next().unwrap_or_default();
    if tag == format!("{channel}-alpine") {
        Vec::new()
    } else {
        vec![format!(
            "Containerfile: builds FROM rust:{tag}, rust-toolchain.toml pins {channel}-alpine"
        )]
    }
}

// --- A crate's clippy.toml ---

/// A crate's `clippy.toml` (or `.clippy.toml`) that does not start, after its own opening comments, with the whole
/// workspace file, comments included: clippy reads the nearest file alone, so a setting of the root one missing there
/// is lost for that crate (D134).
fn clippy_differs(workspace: &str, file: &Source) -> Vec<String> {
    let workspace: Vec<&str> = workspace.lines().collect();
    let lines: Vec<&str> = file.text.lines().collect();
    let comments = lines
        .iter()
        .take_while(|line| line.starts_with('#'))
        .count();
    if (0..=comments).any(|start| {
        lines
            .get(start..)
            .is_some_and(|rest| rest.starts_with(&workspace))
    }) {
        Vec::new()
    } else {
        vec![format!(
            "{}: does not start with the root clippy.toml after its comments",
            file.path
        )]
    }
}

// --- The tree ---

#[test]
fn decisions_cited_exist_and_are_defined_once() {
    let tracked = tracked();
    report(&undefined_or_duplicated(
        &sections(&tracked),
        &citing(&tracked),
    ));
}

#[test]
fn decisions_name_each_other() {
    report(&unpaired(&sections(&tracked())));
}

#[test]
fn the_index_lists_each_decision() {
    report(&index_differs(&read(INDEX), &sections(&tracked())));
}

#[test]
fn coverage_paths_exist() {
    report(&missing_paths(&read(COVERAGE), exists_on_disk));
}

#[test]
fn rfc_test_files_have_a_coverage_row() {
    let files: Vec<Source> = tracked()
        .iter()
        .filter(|path| is_test_file(path))
        .map(|path| read(path))
        .collect();
    report(&missing_rows(&read(COVERAGE), &files));
}

#[test]
fn agents_files_have_their_claude_symlink() {
    report(&missing_links(&tracked(), |path| {
        fs::read_link(root().join(path)).ok()
    }));
}

#[test]
fn crate_clippy_files_repeat_the_root_one() {
    let workspace = read("clippy.toml");
    let problems: Vec<String> = tracked()
        .iter()
        .filter(|path| path.ends_with("/clippy.toml") || path.ends_with("/.clippy.toml"))
        .flat_map(|path| clippy_differs(&workspace.text, &read(path)))
        .collect();
    report(&problems);
}

#[test]
fn image_builds_with_the_pinned_rust() {
    let containerfile =
        fs::read_to_string(root().join("Containerfile")).expect("Containerfile reads");
    let toolchain =
        fs::read_to_string(root().join("rust-toolchain.toml")).expect("toolchain reads");
    report(&image_rust_differs(&containerfile, &toolchain));
}

// --- Each check fails on a small broken input ---

#[test]
fn a_crate_clippy_file_without_the_root_one_fails() {
    let workspace = "a = true\nb = true\n";
    let same = Source::new("x/clippy.toml", "# Why.\na = true\nb = true\n\nc = []\n");
    let other = Source::new("x/clippy.toml", "# Why.\na = true\n\nc = []\n");
    report(&clippy_differs(workspace, &same));
    // The root file's own comments are part of it, not of the crate's.
    let commented = "# Root.\na = true\n";
    let repeated = Source::new("x/clippy.toml", "# Why.\n# Root.\na = true\n");
    report(&clippy_differs(commented, &repeated));
    assert_eq!(
        clippy_differs(
            commented,
            &Source::new("x/clippy.toml", "# Why.\na = true\n")
        )
        .len(),
        1
    );
    assert_eq!(
        clippy_differs(workspace, &other),
        ["x/clippy.toml: does not start with the root clippy.toml after its comments"]
    );
}

#[test]
fn an_image_of_another_rust_fails() {
    let toolchain = "[toolchain]\nchannel = \"1.99.1\"\n";
    let same = "FROM docker.io/library/rust:1.99.1-alpine@sha256:abc AS build\n";
    let other = "FROM docker.io/library/rust:1.99.0-alpine@sha256:abc AS build\n";
    report(&image_rust_differs(same, toolchain));
    assert_eq!(
        image_rust_differs(other, toolchain),
        ["Containerfile: builds FROM rust:1.99.0-alpine, rust-toolchain.toml pins 1.99.1-alpine"]
    );
}

#[test]
fn ids_are_found_in_text() {
    assert_eq!(
        cited("D1, (D7a) D64-D66 D3\u{2013}D4 D9-D8 0xD4 D4D D12_ AD7 D D5sx"),
        ["D1", "D7a", "D64", "D65", "D66", "D3", "D4", "D9", "D8"]
    );
}

#[test]
fn braces_and_stars_expand() {
    assert_eq!(
        expand("a/{b,c/{d,e}}.rs"),
        ["a/b.rs", "a/c/d.rs", "a/c/e.rs"]
    );
    assert_eq!(expand("a/{b"), ["a/{b"]);
    assert!(matches_glob("rfc1035_*.rs", "rfc1035_zone.rs"));
    assert!(!matches_glob("rfc1035_*.rs", "rfc1034_zone.rs"));
}

#[test]
fn undefined_and_duplicated_decisions_fail() {
    let sections = [
        Source::new(
            "docs/decisions/a.md",
            "# A\n\n- D1 One.\n- D2 Cites D3-D4 and D1.\n",
        ),
        Source::new(
            "docs/decisions/b.md",
            "  D6, not defined.\n- D1 Again.\n  More: D5.\n",
        ),
    ];
    let code = Source::new("crates/x/src/lib.rs", "//! D9 and D2\n");
    assert_eq!(
        undefined_or_duplicated(&sections, &[code]),
        [
            "docs/decisions/b.md:2: D1 is defined twice, first at docs/decisions/a.md:3",
            "docs/decisions/a.md:4: D3 is not defined in docs/decisions/",
            "docs/decisions/a.md:4: D4 is not defined in docs/decisions/",
            "docs/decisions/b.md:1: D6 is not defined in docs/decisions/",
            "docs/decisions/b.md:3: D5 is not defined in docs/decisions/",
            "crates/x/src/lib.rs:1: D9 is not defined in docs/decisions/",
        ]
    );
}

#[test]
fn unpaired_decisions_fail() {
    let sections = [
        Source::new(
            "docs/decisions/a.md",
            "- D1 (amends D2; builds on D3) One.\n\
             - D2 Two.\n\
             - D3 (amended by D4-D5) Three.\n\
             - D4 (amends D3) Four.\n",
        ),
        Source::new(
            "docs/decisions/b.md",
            "- D5 (supersedes D6 for UDP; amend D1)\n  Five.\n\
             - D6 (superseded by D7) Six.\n\
             - D7 Seven.\n",
        ),
    ];
    assert_eq!(
        unpaired(&sections),
        [
            "docs/decisions/b.md:1: the header clause \"amend D1\" of D5 has no known relation (amends, amended by, \
             supersedes, superseded by, narrows, narrowed by, builds on, completes)",
            "docs/decisions/a.md:1: D1 amends D2, but D2 (docs/decisions/a.md:2) does not say \"amended by D1\"",
            "docs/decisions/a.md:3: D3 amended by D5, but D5 (docs/decisions/b.md:1) does not say \"amends D3\"",
            "docs/decisions/b.md:1: D5 supersedes D6, but D6 (docs/decisions/b.md:3) does not say \"superseded by D5\"",
            "docs/decisions/b.md:3: D6 superseded by D7, but D7 (docs/decisions/b.md:4) does not say \"supersedes D6\"",
        ]
    );
}

#[test]
fn an_index_out_of_step_fails() {
    let sections = [
        Source::new("docs/decisions/a.md", "- D1 One.\n- D2 (amends D1) Two.\n"),
        Source::new(
            "docs/decisions/b.md",
            "- D3 (builds on D1; amended by D5;\n  superseded by D4) Three.\n- D4 (supersedes D3) Four.\n\
             - D5 (amends D3) Five.\n- D6 Six.\n",
        ),
    ];
    let index = Source::new(
        INDEX,
        "# Decisions\n\n\
         - D1 [a](a.md): one\n\
         - D3 [b](b.md) (amended by D5; superseded by D4): three\n\
         - D2 [a](b.md): two\n\
         - D4 [b](b.md) (amended by D9): four\n\
         - D5 b: five\n\
         - D9 [b](b.md): nine\n",
    );
    assert_eq!(
        index_differs(&index, &sections),
        [
            "docs/decisions/README.md:5: D2 is out of number order",
            "docs/decisions/README.md:5: D2 links b.md, but docs/decisions/a.md defines it",
            "docs/decisions/README.md:6: D4 says (amended by D9), its header ()",
            "docs/decisions/README.md:7: D5 has no [section](file.md) link",
            "docs/decisions/README.md:8: D9 is not defined in docs/decisions/",
            "docs/decisions/b.md:5: D6 has no line in docs/decisions/README.md",
        ]
    );
}

#[test]
fn missing_coverage_paths_fail() {
    let coverage = Source::new(
        COVERAGE,
        "| RFC | Subject | Status | Code | Tests |\n\
         |---|---|---|---|---|\n\
         | [1](https://x/rfc1) | A | done | `crates/a/src/{b,c}.rs`, `Name::x` | `crates/a/tests/rfc1.rs` |\n\
         | [2](https://x/rfc2) | B | done | `crates/a/src/*.txt` | `crates/a/tests/` |\n\
         | [3](https://x/rfc3) | C | done | `crates/a` | `crates/a` | extra |\n",
    );
    let exists = |path: &str| matches!(path, "crates/a/src/b.rs" | "crates/a/tests/rfc1.rs");
    assert_eq!(
        missing_paths(&coverage, exists),
        [
            "docs/rfc/coverage.md:3: crates/a/src/c.rs does not exist",
            "docs/rfc/coverage.md:4: crates/a/src/*.txt does not exist",
            "docs/rfc/coverage.md:4: crates/a/tests/ does not exist",
            "docs/rfc/coverage.md:5: the row has 6 cells, not 5",
        ]
    );
}

#[test]
fn rfc_test_files_without_a_row_fail() {
    let coverage = Source::new(
        COVERAGE,
        "| [1](https://x/rfc1) | A | done | `c` | `crates/a/tests/{wire,text}.rs` |\n\
         | [2](https://x/rfc2) | B | done | `c` | `crates/a/tests/w*.rs` |\n",
    );
    let files = [
        Source::new(
            "crates/a/tests/wire.rs",
            "//! RFC 1 §2, RFC 2 and RFC 1.\n#[test]\nfn f() {} // RFC 9\n",
        ),
        Source::new(
            "crates/a/tests/text.rs",
            "//! What RFC 1 and RFC\n//! 2 say; RFC x.\n#[test]\n",
        ),
        Source::new(
            "apps/b/tests/topic.rs",
            "mod x {\n    //! RFC 3\n    #[test]\n}\n",
        ),
        Source::new("apps/b/tests/util/mod.rs", "//! RFC 7, helpers alone\n"),
        Source::new(
            "crates/a/tests/udp.rs",
            "//! RFC 1 and RFC 8\n#[compio::test]\n",
        ),
        Source::new(
            "crates/a/tests/deep/topic.rs",
            "//! RFCs 9, 10 and 1, §2.\n#[test]\n",
        ),
        Source::new("crates/a/src/lib.rs", "//! RFC 4\n#[test]\n"),
        Source::new("tests/c.rs", "//! RFC 5\n#[test]\n"),
        Source::new("crates/a/tests/notes.md", "//! RFC 6\n#[test]\n"),
    ];
    assert_eq!(
        missing_rows(&coverage, &files),
        [
            "crates/a/tests/text.rs: RFC 2 has a row that does not name it in docs/rfc/coverage.md",
            "apps/b/tests/topic.rs: RFC 3 has no row in docs/rfc/coverage.md",
            "crates/a/tests/udp.rs: RFC 1 has a row that does not name it in docs/rfc/coverage.md",
            "crates/a/tests/udp.rs: RFC 8 has no row in docs/rfc/coverage.md",
            "crates/a/tests/deep/topic.rs: RFC 1 has a row that does not name it in docs/rfc/coverage.md",
            "crates/a/tests/deep/topic.rs: RFC 10 has no row in docs/rfc/coverage.md",
            "crates/a/tests/deep/topic.rs: RFC 9 has no row in docs/rfc/coverage.md",
        ]
    );
}

#[test]
fn agents_files_without_their_symlink_fail() {
    let tracked: Vec<String> = [
        "AGENTS.md",
        "a/AGENTS.md",
        "b/AGENTS.md",
        "b/CLAUDE.md",
        "c/x.md",
    ]
    .map(str::to_owned)
    .into();
    let link = |path: &str| match path {
        "CLAUDE.md" => Some(PathBuf::from("AGENTS.md")),
        "b/CLAUDE.md" => Some(PathBuf::from("OTHER.md")),
        _ => None,
    };
    assert_eq!(
        missing_links(&tracked, link),
        [
            "a/AGENTS.md: no a/CLAUDE.md symlink beside it",
            "b/CLAUDE.md: links to OTHER.md, not to AGENTS.md",
        ]
    );
}
