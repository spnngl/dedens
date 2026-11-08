//! The repository checks (D140): facts the docs rely on, kept true by the gate. Each check is a function of text
//! (or of a closure for the file system), so a small broken input shows it failing; the tests of the tree feed it
//! the tracked files, read from the workspace root.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The decisions, from the workspace root.
const DECISIONS: &str = "docs/decisions.md";
/// The RFC coverage table, from the workspace root.
const COVERAGE: &str = "docs/rfc/coverage.md";
/// Folders whose files cite decisions; `AGENTS.md` files anywhere do too.
const CITING_FOLDERS: [&str; 5] = ["crates/", "apps/", "fuzz/", "docs/", "testdata/"];
/// Extensions of the text files that cite decisions; RFC archives and captured data are not read.
const CITING_EXTENSIONS: [&str; 9] = ["rs", "md", "toml", "yaml", "sh", "go", "c", "py", "nu"];
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

/// The tracked files that may cite a decision, but the decisions themselves. A symlink (`CLAUDE.md`) is its
/// target's copy.
fn citing(tracked: &[String]) -> Vec<Source> {
    let wanted = |path: &str| {
        let file = Path::new(path);
        let text = file
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| CITING_EXTENSIONS.contains(&extension));
        let in_folder = CITING_FOLDERS.iter().any(|folder| path.starts_with(folder));
        file.file_name() == Some(OsStr::new("AGENTS.md"))
            || (text && in_folder && !path.starts_with("docs/rfc/archive/"))
    };
    tracked
        .iter()
        .filter(|path| path.as_str() != DECISIONS && wanted(path))
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

/// A decision's entry in `docs/decisions.md`: a line starting `- D`, and the indented lines after it.
struct Definition {
    id: String,
    line: usize,
    /// The entry on one line, after the id.
    text: String,
}

fn definitions(decisions: &Source) -> Vec<Definition> {
    let mut found: Vec<Definition> = Vec::new();
    for (line, text) in decisions.lines() {
        let start = text
            .strip_prefix("- ")
            .and_then(|_| id_at(text, 2))
            .map(|id| (Id::name(id.number, id.letter), id.end));
        match (start, found.last_mut()) {
            (Some((id, end)), _) => found.push(Definition {
                id,
                line,
                text: text[end..].to_owned(),
            }),
            (None, Some(open)) if text.starts_with(' ') => {
                open.text.push(' ');
                open.text.push_str(text.trim());
            }
            (None, _) => {}
        }
    }
    found
}

/// A decision defined twice, a decision cited (in `decisions` or in `others`) and defined nowhere.
fn undefined_or_duplicated(decisions: &Source, others: &[Source]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut defined: BTreeMap<String, usize> = BTreeMap::new();
    for definition in definitions(decisions) {
        if let Some(first) = defined.get(&definition.id) {
            problems.push(decisions.problem(
                definition.line,
                &format!("{} is defined twice, first on line {first}", definition.id),
            ));
        } else {
            defined.insert(definition.id, definition.line);
        }
    }
    for source in std::iter::once(decisions).chain(others) {
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
}

/// A decision's relations to others, from its header.
struct Entry {
    id: String,
    line: usize,
    relations: BTreeSet<(Relation, String)>,
}

/// What the header of a definition says, `(amends D2; amended by D5, D6)`: its relations, and the clauses that
/// name decisions in no known form (`(amend D2)` would otherwise pass for no relation).
fn relations(definition: &Definition) -> (Entry, Vec<String>) {
    let mut entry = Entry {
        id: definition.id.clone(),
        line: definition.line,
        relations: BTreeSet::new(),
    };
    let mut unknown = Vec::new();
    let Some(header) = definition
        .text
        .strip_prefix(" (")
        .and_then(|inner| inner.split_once(')'))
        .map(|(header, _)| header)
    else {
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
            None if !cited(clause).is_empty() => unknown.push(format!(
                "the header clause {clause:?} of {} has no known relation (amends, amended by, supersedes, \
                 superseded by, narrows, narrowed by, builds on, completes)",
                definition.id
            )),
            None => {}
        }
    }
    (entry, unknown)
}

/// A decision that amends, supersedes or narrows another which does not say so back, and the reverse. A
/// supersession limited to a scope (`superseded by D113 for UDP`) is one still: the two sides name each other.
fn unpaired(decisions: &Source) -> Vec<String> {
    let mut problems = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    for definition in definitions(decisions) {
        let (entry, unknown) = relations(&definition);
        problems.extend(unknown.iter().map(|m| decisions.problem(entry.line, m)));
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
                problems.push(decisions.problem(
                    entry.line,
                    &format!(
                        "{} {} {other}, but {other} (line {}) does not say \"{} {}\"",
                        entry.id,
                        relation.phrase(),
                        other_entry.line,
                        back.phrase(),
                        entry.id
                    ),
                ));
            }
        }
    }
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

/// A `tests/rfcNNNN.rs` of a crate or an app whose RFC has no row in the table.
fn missing_rows(coverage: &Source, tracked: &[String]) -> Vec<String> {
    let covered: BTreeSet<&str> = rows(coverage)
        .filter_map(|(_, cells)| {
            let first = *cells.get(1)?;
            first.split("rfc").nth(1)
        })
        .map(|rest| &rest[..rest.bytes().take_while(u8::is_ascii_digit).count()])
        .collect();
    tracked
        .iter()
        .filter_map(|path| {
            let file = Path::new(path);
            let number = file.file_stem()?.to_str()?.strip_prefix("rfc")?;
            let in_tests = file.parent()?.file_name()? == "tests";
            let owned = path.starts_with("crates/") || path.starts_with("apps/");
            let is_test = file.extension()? == "rs"
                && !number.is_empty()
                && number.bytes().all(|b| b.is_ascii_digit());
            (in_tests && owned && is_test && !covered.contains(number))
                .then(|| format!("{path}: RFC {number} has no row in {COVERAGE}"))
        })
        .collect()
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
    report(&undefined_or_duplicated(
        &read(DECISIONS),
        &citing(&tracked()),
    ));
}

#[test]
fn decisions_name_each_other() {
    report(&unpaired(&read(DECISIONS)));
}

#[test]
fn coverage_paths_exist() {
    report(&missing_paths(&read(COVERAGE), exists_on_disk));
}

#[test]
fn rfc_test_files_have_a_coverage_row() {
    report(&missing_rows(&read(COVERAGE), &tracked()));
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
    let decisions = Source::new(
        DECISIONS,
        "- D1 One.\n- D1 Again.\n- D2 Cites D3-D4 and D1.\n  More: D5.\n",
    );
    let code = Source::new("crates/x/src/lib.rs", "//! D9 and D2\n");
    assert_eq!(
        undefined_or_duplicated(&decisions, &[code]),
        [
            "docs/decisions.md:2: D1 is defined twice, first on line 1",
            "docs/decisions.md:3: D3 is not defined in docs/decisions.md",
            "docs/decisions.md:3: D4 is not defined in docs/decisions.md",
            "docs/decisions.md:4: D5 is not defined in docs/decisions.md",
            "crates/x/src/lib.rs:1: D9 is not defined in docs/decisions.md",
        ]
    );
}

#[test]
fn unpaired_decisions_fail() {
    let decisions = Source::new(
        DECISIONS,
        "- D1 (amends D2; builds on D3) One.\n\
         - D2 Two.\n\
         - D3 (amended by D4-D5) Three.\n\
         - D4 (amends D3) Four.\n\
         - D5 (supersedes D6 for UDP; amend D1)\n  Five.\n\
         - D6 (superseded by D7) Six.\n\
         - D7 Seven.\n",
    );
    assert_eq!(
        unpaired(&decisions),
        [
            "docs/decisions.md:5: the header clause \"amend D1\" of D5 has no known relation (amends, amended by, \
             supersedes, superseded by, narrows, narrowed by, builds on, completes)",
            "docs/decisions.md:1: D1 amends D2, but D2 (line 2) does not say \"amended by D1\"",
            "docs/decisions.md:3: D3 amended by D5, but D5 (line 5) does not say \"amends D3\"",
            "docs/decisions.md:5: D5 supersedes D6, but D6 (line 7) does not say \"superseded by D5\"",
            "docs/decisions.md:7: D6 superseded by D7, but D7 (line 8) does not say \"supersedes D6\"",
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
    let coverage = Source::new(COVERAGE, "| [1](https://x/rfc1) | A | done | `c` | `t` |\n");
    let tracked: Vec<String> = [
        "crates/a/tests/rfc1.rs",
        "crates/a/tests/rfc2.rs",
        "apps/b/tests/rfc3.rs",
        "crates/a/tests/rfc2_extra.rs",
        "crates/a/src/rfc4.rs",
        "tests/rfc5.rs",
    ]
    .map(str::to_owned)
    .into();
    assert_eq!(
        missing_rows(&coverage, &tracked),
        [
            "crates/a/tests/rfc2.rs: RFC 2 has no row in docs/rfc/coverage.md",
            "apps/b/tests/rfc3.rs: RFC 3 has no row in docs/rfc/coverage.md",
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
