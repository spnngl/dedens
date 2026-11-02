//! The lists read, kept across reloads (D120).
//!
//! A list is read once, whatever the number of stages naming it, and again only when its source changed: a reload
//! or a download of one list leaves the others as they are. [`Store`] holds one [`Names`] per source and one
//! [`Merged`] per set of sources a stage side reads; the stages take clones, which share them.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, anyhow};
use dedens_plugins::{ListError, Merged, Names, Tlds};

/// The byte order mark some editors put at the start of a file.
const BOM: char = '\u{feff}';

/// Where a list comes from, with what its reading depends on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Source {
    /// The `entries` of a stage, read as `tlds` says.
    Inline { entries: Vec<String>, tlds: Tlds },
    /// The `file` of a stage, read as `tlds` says.
    File { path: PathBuf, tlds: Tlds },
    /// The saved copy of a downloaded list, read the same for every stage.
    Copy(PathBuf),
}

/// What tells that a file is the one read, as git tells that a file changed: taken from the handle the file is read
/// through, so that it describes what is read, and before the reading, so that a change during it shows at the
/// next. No content hash: it would read every list at every reload, which is the cost kept off.
///
/// The change time is the one an editor or `touch` cannot set back, so a rewrite of the same size under the old
/// modification time still shows; the device and inode show a file replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: SystemTime,
    #[cfg(unix)]
    file: (u64, u64),
    #[cfg(unix)]
    changed: (i64, i64),
}

impl Stamp {
    fn of(file: &File) -> io::Result<Self> {
        let meta = file.metadata()?;
        #[cfg(unix)]
        let (file, changed) = {
            use std::os::unix::fs::MetadataExt as _;
            ((meta.dev(), meta.ino()), (meta.ctime(), meta.ctime_nsec()))
        };
        Ok(Self {
            len: meta.len(),
            modified: meta.modified()?,
            #[cfg(unix)]
            file,
            #[cfg(unix)]
            changed,
        })
    }
}

#[derive(Debug)]
struct Held {
    /// None for entries: they are part of the [`Source`].
    stamp: Option<Stamp>,
    names: Names,
    /// Whether the reading under way used it: what is not is dropped at its end.
    used: bool,
}

/// The set a stage side read from `sources`, when read as `tlds` says.
#[derive(Debug)]
struct Union {
    tlds: Tlds,
    sources: Vec<Names>,
    merged: Merged,
    used: bool,
}

/// The lists read so far, by source, and the sets built from them. Owned by the thread reloading, which hands it to
/// every reading of the configuration and to the downloads.
#[derive(Debug, Default)]
pub(crate) struct Store {
    held: HashMap<Source, Held>,
    unions: Vec<Union>,
}

impl Store {
    /// Starts a reading of the configuration: nothing is used yet.
    pub(crate) fn begin(&mut self) {
        for held in self.held.values_mut() {
            held.used = false;
        }
        for union in &mut self.unions {
            union.used = false;
        }
    }

    /// Ends a reading of the configuration that succeeded: what it did not use is dropped, so that the store holds
    /// the lists of the configuration and no more.
    pub(crate) fn end(&mut self) {
        self.held.retain(|_, held| held.used);
        self.unions.retain(|union| union.used);
    }

    /// The names of the `entries` of a stage, read as `tlds` says; none for no entries.
    ///
    /// # Errors
    ///
    /// An entry that is not a name, located by its number.
    pub(crate) fn entries(
        &mut self,
        entries: &[String],
        tlds: Tlds,
    ) -> anyhow::Result<Option<Names>> {
        if entries.is_empty() {
            return Ok(None);
        }
        let source = Source::Inline {
            entries: entries.to_vec(),
            tlds,
        };
        if let Some(held) = self.held.get_mut(&source) {
            held.used = true;
            return Ok(Some(held.names.clone()));
        }
        let mut text = String::new();
        for entry in entries {
            text.push_str(entry);
            text.push('\n');
        }
        let names = Names::local(tlds, &text).map_err(|error| located(error, "entry"))?;
        tracing::info!(kind = "entries", names = names.len(), "list parsed");
        Ok(Some(self.insert(source, None, names)))
    }

    /// The names of the lines of the file at `path`, its byte order mark left out, read as `tlds` says.
    ///
    /// # Errors
    ///
    /// A file that cannot be read, or a line that is not a name, located by its number.
    pub(crate) fn file(&mut self, path: &Path, tlds: Tlds) -> anyhow::Result<Names> {
        let reading = || format!("reading `{}`", path.display());
        let mut file = File::open(path).with_context(reading)?;
        let stamp = Stamp::of(&file).with_context(reading)?;
        let source = Source::File {
            path: path.to_owned(),
            tlds,
        };
        if let Some(names) = self.reuse(&source, stamp) {
            return Ok(names);
        }
        let mut text = String::new();
        file.read_to_string(&mut text).with_context(reading)?;
        let text = text.strip_prefix(BOM).unwrap_or(&text);
        let names = Names::local(tlds, text)
            .map_err(|error| located(error, &format!("`{}` line", path.display())))?;
        tracing::info!(kind = "file", file = %path.display(), names = names.len(), "list parsed");
        Ok(self.insert(source, Some(stamp), names))
    }

    /// The names of the saved `copy` of the list at `url` (redacted).
    ///
    /// # Errors
    ///
    /// The copy cannot be read: [`io::ErrorKind::NotFound`] when there is none yet.
    pub(crate) fn saved(&mut self, copy: &Path, url: &str) -> io::Result<Names> {
        let mut file = File::open(copy)?;
        let stamp = Stamp::of(&file)?;
        let source = Source::Copy(copy.to_owned());
        if let Some(names) = self.reuse(&source, stamp) {
            return Ok(names);
        }
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let names = Names::downloaded(&text);
        tracing::info!(kind = "saved copy", url, names = names.len(), "list parsed");
        Ok(self.insert(source, Some(stamp), names))
    }

    /// Keeps the `names` the downloader read from the text it just saved as `copy`, so that the next reading of
    /// the configuration does not read the copy again.
    pub(crate) fn keep(&mut self, copy: &Path, names: Names) {
        if let Ok(stamp) = File::open(copy).and_then(|file| Stamp::of(&file)) {
            self.insert(Source::Copy(copy.to_owned()), Some(stamp), names);
        }
    }

    /// The names of `sources` as one set, for a stage side reading them as `tlds` says: the one built for the same
    /// sources, if any, else a new one. None, an empty set.
    ///
    /// # Errors
    ///
    /// [`ListError::NotAList`] for a downloaded source that is not a list, which [`Names::check`] says first.
    pub(crate) fn merged(&mut self, tlds: Tlds, sources: &[Names]) -> anyhow::Result<Merged> {
        if sources.is_empty() {
            return Ok(Merged::default());
        }
        if let Some(union) = self.unions.iter_mut().find(|union| {
            union.tlds == tlds
                && union.sources.len() == sources.len()
                && union.sources.iter().zip(sources).all(|(a, b)| a.same(b))
        }) {
            union.used = true;
            return Ok(union.merged.clone());
        }
        let merged = Merged::new(tlds, sources)?;
        tracing::info!(
            sources = sources.len(),
            names = merged.len(),
            "lists merged"
        );
        self.unions.push(Union {
            tlds,
            sources: sources.to_vec(),
            merged: merged.clone(),
            used: true,
        });
        Ok(merged)
    }

    /// The names held for `source` if `stamp` is the one they were read under, now used.
    fn reuse(&mut self, source: &Source, stamp: Stamp) -> Option<Names> {
        let held = self
            .held
            .get_mut(source)
            .filter(|held| held.stamp == Some(stamp))?;
        held.used = true;
        Some(held.names.clone())
    }

    /// Holds `names` for `source`, used, and returns them to share.
    fn insert(&mut self, source: Source, stamp: Option<Stamp>, names: Names) -> Names {
        self.held.insert(
            source,
            Held {
                stamp,
                names: names.clone(),
                used: true,
            },
        );
        names
    }
}

/// `error` of a list read as `what` and its line number says: `entry 3: …` or `` `list.txt` line 3: … ``.
fn located(error: ListError, what: &str) -> anyhow::Error {
    match error {
        ListError::Line(error) => anyhow!("{what} {}: {}", error.line, error.kind),
        error => anyhow!(error),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, text).expect("a file in a temporary directory");
        path
    }

    #[test]
    fn entries_are_read_once() {
        let mut store = Store::default();
        let entries = vec!["ads.example".to_owned(), "*.track.example".to_owned()];
        let first = store.entries(&entries, Tlds::Refuse).unwrap().unwrap();
        let second = store.entries(&entries, Tlds::Refuse).unwrap().unwrap();
        assert!(first.same(&second));
        // Read as another `tlds` says is another reading.
        let allowed = store.entries(&entries, Tlds::Allow).unwrap().unwrap();
        assert!(!first.same(&allowed));
        assert!(store.entries(&[], Tlds::Refuse).unwrap().is_none());
    }

    #[test]
    fn an_entry_that_is_not_a_name_is_located() {
        let mut store = Store::default();
        let entries = vec!["ads.example".to_owned(), "not a name".to_owned()];
        let error = store.entries(&entries, Tlds::Refuse).unwrap_err();
        assert!(error.to_string().starts_with("entry 2: "), "{error}");
    }

    /// Rewrites `path` in place with `text`, its modification time put back: what an editor or a tool that keeps
    /// times does.
    fn rewrite_keeping_time(path: &Path, text: &str) {
        let modified = fs::metadata(path).unwrap().modified().unwrap();
        fs::write(path, text).unwrap();
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }

    #[test]
    fn a_file_is_read_once_until_it_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "list.txt", "ads.example\n");
        let mut store = Store::default();
        let first = store.file(&path, Tlds::Refuse).unwrap();
        assert!(first.same(&store.file(&path, Tlds::Refuse).unwrap()));
        // Read as another `tlds` says is another reading.
        assert!(!first.same(&store.file(&path, Tlds::Allow).unwrap()));
        write(dir.path(), "list.txt", "ads.example\ntrack.example\n");
        let second = store.file(&path, Tlds::Refuse).unwrap();
        assert!(!first.same(&second));
        assert_eq!(second.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_rewritten_to_the_same_size_and_time_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "list.txt", "ads.example\n");
        let mut store = Store::default();
        let first = store.file(&path, Tlds::Refuse).unwrap();
        rewrite_keeping_time(&path, "adz.example\n");
        assert!(!first.same(&store.file(&path, Tlds::Refuse).unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_replaced_by_another_of_the_same_size_and_time_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "list.txt", "ads.example\n");
        let mut store = Store::default();
        let first = store.file(&path, Tlds::Refuse).unwrap();
        let other = write(dir.path(), "other.txt", "adz.example\n");
        File::options()
            .write(true)
            .open(&other)
            .unwrap()
            .set_modified(fs::metadata(&path).unwrap().modified().unwrap())
            .unwrap();
        fs::rename(&other, &path).unwrap();
        assert!(!first.same(&store.file(&path, Tlds::Refuse).unwrap()));
    }

    #[test]
    fn a_byte_order_mark_is_not_part_of_the_first_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "list.txt", "\u{feff}ads.example\n");
        let names = Store::default().file(&path, Tlds::Refuse).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn a_line_that_is_not_a_name_is_located_in_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "list.txt", "ads.example\n\nnot a name\n");
        let error = Store::default().file(&path, Tlds::Refuse).unwrap_err();
        assert!(error.to_string().contains("list.txt` line 3: "), "{error}");
    }

    #[test]
    fn a_missing_file_is_an_error_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.txt");
        let error = Store::default().file(&path, Tlds::Refuse).unwrap_err();
        assert!(error.to_string().starts_with("reading `"), "{error}");
    }

    #[test]
    fn a_saved_copy_is_read_again_when_the_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let copy = write(dir.path(), "a.list", "ads.example\n");
        let mut store = Store::default();
        let first = store.saved(&copy, "http://list").unwrap();
        assert!(first.same(&store.saved(&copy, "http://list").unwrap()));
        write(dir.path(), "a.list", "ads.example\ntrack.example\n");
        let second = store.saved(&copy, "http://list").unwrap();
        assert!(!first.same(&second));
        assert_eq!(second.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_copy_rewritten_to_the_same_size_and_time_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let copy = write(dir.path(), "a.list", "ads.example\n");
        let mut store = Store::default();
        let first = store.saved(&copy, "http://list").unwrap();
        rewrite_keeping_time(&copy, "adz.example\n");
        assert!(!first.same(&store.saved(&copy, "http://list").unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_copy_that_cannot_be_read_is_an_error_even_when_held() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let copy = write(dir.path(), "a.list", "ads.example\n");
        let mut store = Store::default();
        store.saved(&copy, "http://list").unwrap();
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o000)).unwrap();
        // A superuser reads it all the same.
        if File::open(&copy).is_err() {
            let error = store.saved(&copy, "http://list").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn a_missing_copy_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let error = Store::default()
            .saved(&dir.path().join("a.list"), "http://list")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_copy_the_downloader_kept_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let copy = write(dir.path(), "a.list", "ads.example\n");
        let mut store = Store::default();
        let downloaded = Names::downloaded("ads.example\n");
        store.keep(&copy, downloaded.clone());
        assert!(downloaded.same(&store.saved(&copy, "http://list").unwrap()));
    }

    #[test]
    fn the_same_sources_are_one_set() {
        let mut store = Store::default();
        let a = store
            .entries(&["ads.example".to_owned()], Tlds::Refuse)
            .unwrap()
            .unwrap();
        let b = store
            .entries(&["track.example".to_owned()], Tlds::Refuse)
            .unwrap()
            .unwrap();
        let first = store.merged(Tlds::Refuse, &[a.clone(), b.clone()]).unwrap();
        assert_eq!(first.len(), 2);
        assert!(first.shares(&store.merged(Tlds::Refuse, &[a.clone(), b.clone()]).unwrap()));
        // Another source, another order or another setting is another set.
        assert!(!first.shares(&store.merged(Tlds::Refuse, &[b.clone(), a.clone()]).unwrap()));
        assert!(
            !first.shares(
                &store
                    .merged(Tlds::Refuse, std::slice::from_ref(&a))
                    .unwrap()
            )
        );
        assert!(!first.shares(&store.merged(Tlds::Allow, &[a, b]).unwrap()));
        assert!(store.merged(Tlds::Refuse, &[]).unwrap().is_empty());
    }

    #[test]
    fn what_a_reading_did_not_use_is_dropped_at_its_end() {
        let mut store = Store::default();
        let kept = vec!["ads.example".to_owned()];
        let dropped = vec!["track.example".to_owned()];
        let first = store.entries(&kept, Tlds::Refuse).unwrap().unwrap();
        let before = store.entries(&dropped, Tlds::Refuse).unwrap().unwrap();
        store
            .merged(Tlds::Refuse, std::slice::from_ref(&first))
            .unwrap();
        store
            .merged(Tlds::Refuse, std::slice::from_ref(&before))
            .unwrap();
        store.begin();
        let kept_again = store.entries(&kept, Tlds::Refuse).unwrap().unwrap();
        store.merged(Tlds::Refuse, &[kept_again]).unwrap();
        store.end();
        assert_eq!(store.held.len(), 1);
        assert_eq!(store.unions.len(), 1);
        assert!(first.same(&store.entries(&kept, Tlds::Refuse).unwrap().unwrap()));
        assert!(!before.same(&store.entries(&dropped, Tlds::Refuse).unwrap().unwrap()));
    }
}
