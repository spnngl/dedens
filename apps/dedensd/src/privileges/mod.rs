//! Dropping root (D122, S5): a server started as root to bind :53, :443 or :853 gives it up once every socket is
//! bound and every file that needs it is read, before any thread serves, so that a flaw reached through hostile input
//! finds a user that owns nothing.
//!
//! The target is `user:` (a name or a numeric id, as `group:`) of the configuration. [`plan`] resolves it while the
//! process is still root, before any socket is bound, so that a mistake fails the start early; [`apply`] drops
//! after the sockets are bound: the groups listing the user (and `group`, none for a user without an entry), the
//! group, the user; then it checks that root cannot come back (every id, no group 0, `setuid(0)` refused), that no
//! capability is left, and sets `PR_SET_NO_NEW_PRIVS`. It runs before the first thread is started, and `setuid` is
//! libc's, which changes the whole process: no thread keeps root, and `NO_NEW_PRIVS`, a flag of the thread that sets
//! it and of those it starts, reaches them all; a process with a second thread is refused. Only Linux drops (D122):
//! `PR_SET_NO_NEW_PRIVS` and `/proc/PID/status`, which the checks read, are Linux's, and nothing else is tested.

use std::fmt;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde::Deserialize;

/// A user or a group, as written in the configuration: a name, or an all-digits id (as in `systemd`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) enum Account {
    Name(String),
    Id(u32),
}

impl TryFrom<String> for Account {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        if text.is_empty() || text.contains(char::is_control) {
            return Err("a name, or a numeric id".into());
        }
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(Self::Name(text));
        }
        match text.parse::<u32>() {
            // `-1` as an id is the "no change" of `chown(2)`, never an account.
            Ok(id) if id != u32::MAX => Ok(Self::Id(id)),
            _ => Err(format!("`{text}` is not a user or group id")),
        }
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::Id(id) => write!(f, "{id}"),
        }
    }
}

/// Who to run as once the sockets are bound: `user:` and `group:`. A reload cannot change it, and warns of a
/// change in what is written, not in who it names (`user: 990` for `user: dedens` warns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    user: Account,
    group: Option<Account>,
}

impl Identity {
    /// The identity `user` and `group` of a configuration say, `None` for neither; `supported` tells whether this
    /// OS can drop privileges.
    ///
    /// # Errors
    ///
    /// A `group` without a `user`; a `user` where the drop is not supported.
    pub(crate) fn new(
        user: Option<Account>,
        group: Option<Account>,
        supported: bool,
    ) -> anyhow::Result<Option<Self>> {
        match (user, group) {
            (None, None) => Ok(None),
            (None, Some(_)) => bail!("`group` needs a `user`"),
            (Some(_), _) if !supported => {
                bail!(
                    "`user` drops privileges on Linux only: leave it out, and run as the user wanted"
                )
            }
            (Some(user), group) => Ok(Some(Self { user, group })),
        }
    }
}

/// The passwd entry of a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Its name, to find the groups that list it by.
    pub(crate) name: String,
    /// Its primary group.
    pub(crate) gid: u32,
}

/// A user, as the system knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) uid: u32,
    /// `None` for a numeric id with no entry: a service account kept out of `/etc/passwd`.
    pub(crate) entry: Option<Entry>,
}

/// The users and groups of the system.
pub(crate) trait Accounts {
    /// The user `account`.
    ///
    /// # Errors
    ///
    /// A name nobody has, or a lookup that failed.
    fn user(&self, account: &Account) -> anyhow::Result<Member>;

    /// The id of the group `account`.
    ///
    /// # Errors
    ///
    /// A name no group has, or a lookup that failed.
    fn group(&self, account: &Account) -> anyhow::Result<u32>;
}

/// Who the process runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ids {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// What to run as after the sockets are bound.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// No `user` and not root: nothing to drop.
    Unprivileged,
    /// No `user`, and root: kept, with a warning.
    Root,
    /// Already the user and the group asked for.
    Already,
    /// Becomes the user and the group.
    Drop { user: Member, gid: u32 },
}

/// Resolves `identity` while the process still is root: what to become, and whether it can.
///
/// # Errors
///
/// A user or a group that does not exist; a numeric user with no entry and no `group`; a `user` that is root, or a
/// `group` that is; a `user` when not root, unless it is the user and the group the process runs as.
pub(crate) fn plan(
    identity: Option<&Identity>,
    current: Ids,
    accounts: &impl Accounts,
) -> anyhow::Result<Plan> {
    let root = current.uid == 0;
    let Some(Identity { user, group }) = identity else {
        return Ok(if root { Plan::Root } else { Plan::Unprivileged });
    };
    let member = accounts.user(user)?;
    let gid = match (group, &member.entry) {
        (Some(group), _) => accounts.group(group)?,
        (None, Some(entry)) => entry.gid,
        (None, None) => {
            bail!("`user` {user} has no entry to take its group from: set `group`")
        }
    };
    if !root {
        ensure!(
            member.uid == current.uid && gid == current.gid,
            "`user` {user} needs a server started as root: it runs as uid {} and gid {}",
            current.uid,
            current.gid
        );
        return Ok(Plan::Already);
    }
    ensure!(
        member.uid != 0,
        "`user` {user} is root: nothing would be dropped"
    );
    ensure!(
        gid != 0,
        "the group of `user` {user} is root (gid 0): set `group`"
    );
    Ok(Plan::Drop { user: member, gid })
}

/// [`plan`] for the process and the system it runs on.
///
/// # Errors
///
/// As [`plan`]; a process that is not root and whose ids differ.
pub(crate) fn resolve(identity: Option<&Identity>) -> anyhow::Result<Plan> {
    plan(identity, ids()?, &System)
}

/// The drop `plan` decided, after every socket is bound and every file read at start that needs it; it creates what
/// the dropped user must write first ([`os::prepare`]), and logs it. `downloads` is the directory of the lists to
/// download, if the configuration has any: one that `urls` adds at a reload needs a directory the user can write
/// already.
///
/// # Errors
///
/// A call the OS refuses, or one that left a way back to root: the process must then end, it may be half dropped;
/// a second thread; a `downloads` directory the user cannot write.
pub(crate) fn apply(plan: Plan, downloads: Option<&Path>) -> anyhow::Result<()> {
    match plan {
        Plan::Unprivileged => {}
        Plan::Root => tracing::warn!(
            "running as root: set `user` to drop privileges once the sockets are bound (D122)"
        ),
        Plan::Already => {
            let caps = os::seal()?;
            tracing::info!(
                effective = caps.effective(),
                permitted = caps.permitted(),
                ambient = caps.ambient(),
                "already the user: nothing to drop, no new privileges (D122)"
            );
        }
        Plan::Drop { user, gid } => {
            if let Some(dir) = downloads {
                os::prepare(dir, user.uid, gid)?;
            }
            os::drop_to(&user, gid)?;
            if let Some(dir) = downloads {
                tempfile::tempfile_in(dir).with_context(|| {
                    format!(
                        "`downloads.dir` {} is not writable by uid {}: chown it",
                        dir.display(),
                        user.uid
                    )
                })?;
            }
            tracing::info!(
                uid = user.uid,
                gid,
                user = user.entry.map(|entry| entry.name),
                "dropped privileges (D122)"
            );
        }
    }
    Ok(())
}

/// The value of the field `name` of a `/proc/PID/status` text.
fn field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
}

/// The capability masks of a `/proc/PID/status` text, the ones a process can use or raise again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Caps {
    permitted: u64,
    effective: u64,
    ambient: u64,
}

impl Caps {
    /// The masks of `status`; a field it lacks (no `/proc`, an old kernel) is no capability: the check is a belt,
    /// `setuid(0)` refused is the proof.
    fn read(status: &str) -> Self {
        let mask = |name| {
            field(status, name)
                .and_then(|mask| u64::from_str_radix(mask, 16).ok())
                .unwrap_or(0)
        };
        Self {
            permitted: mask("CapPrm"),
            effective: mask("CapEff"),
            ambient: mask("CapAmb"),
        }
    }

    /// Whether none is left.
    const fn none(self) -> bool {
        self.permitted == 0 && self.effective == 0 && self.ambient == 0
    }

    fn permitted(self) -> String {
        format!("{:016x}", self.permitted)
    }

    fn effective(self) -> String {
        format!("{:016x}", self.effective)
    }

    fn ambient(self) -> String {
        format!("{:016x}", self.ambient)
    }
}

/// Whether the process has one thread, by the `Threads` field of a `/proc/PID/status` text; unread is yes.
fn alone(status: &str) -> bool {
    field(status, "Threads").is_none_or(|threads| threads == "1")
}

// Each in a file of its own; the mutation tests leave `not_unix` out: they run where it is not built (D142).
#[cfg(not(unix))]
mod not_unix;
#[cfg(unix)]
mod unix;

pub(crate) use os::{System, ids, in_group};

#[cfg(not(unix))]
use self::not_unix as os;
#[cfg(unix)]
use self::unix as os;

#[cfg(test)]
mod tests {
    use super::*;

    /// Users `dedens` (uid 990, gid 990), `nobody` (65534, 65534) and `root`, groups `dedens` (990) and `ssl` (101).
    struct Fake;

    impl Accounts for Fake {
        fn user(&self, account: &Account) -> anyhow::Result<Member> {
            let member = |uid, name: &str| Member {
                uid,
                entry: Some(Entry {
                    name: name.into(),
                    gid: uid,
                }),
            };
            match account {
                Account::Name(name) if name == "dedens" => Ok(member(990, "dedens")),
                Account::Name(name) if name == "root" => Ok(member(0, "root")),
                Account::Id(990) => Ok(member(990, "dedens")),
                Account::Id(0) => Ok(member(0, "root")),
                Account::Id(uid @ 5000) => Ok(Member {
                    uid: *uid,
                    entry: None,
                }),
                other => bail!("no user {other}"),
            }
        }

        fn group(&self, account: &Account) -> anyhow::Result<u32> {
            match account {
                Account::Name(name) if name == "ssl" => Ok(101),
                Account::Name(name) if name == "root" => Ok(0),
                Account::Id(gid) => Ok(*gid),
                other @ Account::Name(_) => bail!("no group {other}"),
            }
        }
    }

    const ROOT: Ids = Ids { uid: 0, gid: 0 };

    fn identity(user: &str, group: Option<&str>) -> Identity {
        let account = |text: &str| Account::try_from(text.to_owned()).unwrap();
        Identity::new(Some(account(user)), group.map(account), true)
            .unwrap()
            .unwrap()
    }

    fn refused(identity: Option<&Identity>, current: Ids) -> String {
        format!("{:#}", plan(identity, current, &Fake).expect_err("refused"))
    }

    /// D122: a name is a name, digits are an id, and nothing else is either.
    #[test]
    fn an_account_is_a_name_or_an_id() {
        let account = |text: &str| Account::try_from(text.to_owned());
        assert_eq!(account("dedens"), Ok(Account::Name("dedens".into())));
        assert_eq!(account("_dns-1"), Ok(Account::Name("_dns-1".into())));
        assert_eq!(account("1000"), Ok(Account::Id(1000)));
        assert_eq!(account("0"), Ok(Account::Id(0)));
        assert_eq!(account("4294967294"), Ok(Account::Id(u32::MAX - 1)));
        // `(uid_t)-1` and past 32 bits are no id; neither is anything of no characters or a control one.
        for text in [
            "4294967295",
            "4294967296",
            "99999999999999999999",
            "",
            "a\0b",
            "a\nb",
        ] {
            assert!(account(text).is_err(), "{text:?}");
        }
    }

    /// D122: `group` goes with `user`, and `user` needs an OS that can drop.
    #[test]
    fn a_group_needs_a_user_and_a_user_needs_linux() {
        let dedens = Some(Account::Name("dedens".into()));
        assert_eq!(Identity::new(None, None, true).unwrap(), None);
        assert_eq!(Identity::new(None, None, false).unwrap(), None);
        assert!(Identity::new(dedens.clone(), None, true).unwrap().is_some());
        let error = Identity::new(None, dedens.clone(), true).unwrap_err();
        assert_eq!(error.to_string(), "`group` needs a `user`");
        let error = Identity::new(dedens, None, false).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("`user` drops privileges on Linux only"),
            "{error}"
        );
    }

    /// D122: root without `user` stays, with a warning; anyone else without one has nothing to drop.
    #[test]
    fn without_a_user_nothing_is_dropped() {
        assert_eq!(plan(None, ROOT, &Fake).unwrap(), Plan::Root);
        assert_eq!(
            plan(None, Ids { uid: 7, gid: 7 }, &Fake).unwrap(),
            Plan::Unprivileged
        );
    }

    /// D122: root drops to the group of the user, or to `group`; a numeric id with an entry is its user.
    #[test]
    fn root_drops_to_the_user() {
        let dedens = Member {
            uid: 990,
            entry: Some(Entry {
                name: "dedens".into(),
                gid: 990,
            }),
        };
        assert_eq!(
            plan(Some(&identity("dedens", None)), ROOT, &Fake).unwrap(),
            Plan::Drop {
                user: dedens.clone(),
                gid: 990
            }
        );
        assert_eq!(
            plan(Some(&identity("990", None)), ROOT, &Fake).unwrap(),
            Plan::Drop {
                user: dedens.clone(),
                gid: 990
            }
        );
        assert_eq!(
            plan(Some(&identity("dedens", Some("ssl"))), ROOT, &Fake).unwrap(),
            Plan::Drop {
                user: dedens,
                gid: 101
            }
        );
        // A numeric id with no entry has no group and no supplementary groups: `group` says which.
        let nameless = Member {
            uid: 5000,
            entry: None,
        };
        assert_eq!(
            plan(Some(&identity("5000", Some("5000"))), ROOT, &Fake).unwrap(),
            Plan::Drop {
                user: nameless,
                gid: 5000
            }
        );
        assert!(refused(Some(&identity("5000", None)), ROOT).contains("set `group`"));
    }

    /// D122: no user, no group, and neither root: refused before any socket is bound.
    #[test]
    fn a_target_must_exist_and_not_be_root() {
        assert!(refused(Some(&identity("ghost", None)), ROOT).contains("no user ghost"));
        assert!(refused(Some(&identity("dedens", Some("ghost"))), ROOT).contains("no group ghost"));
        assert!(refused(Some(&identity("root", None)), ROOT).contains("is root"));
        assert!(refused(Some(&identity("0", None)), ROOT).contains("is root"));
        assert!(refused(Some(&identity("dedens", Some("root"))), ROOT).contains("gid 0"));
    }

    /// D122: a server not started as root cannot become another user, but is the one asked for already.
    #[test]
    fn without_root_the_user_must_be_the_one_running() {
        let dedens = Ids { uid: 990, gid: 990 };
        assert_eq!(
            plan(Some(&identity("dedens", None)), dedens, &Fake).unwrap(),
            Plan::Already
        );
        assert_eq!(
            plan(Some(&identity("990", Some("990"))), dedens, &Fake).unwrap(),
            Plan::Already
        );
        let error = refused(
            Some(&identity("dedens", None)),
            Ids {
                uid: 1000,
                gid: 1000,
            },
        );
        assert_eq!(
            error,
            "`user` dedens needs a server started as root: it runs as uid 1000 and gid 1000"
        );
        // The user, with another group: it cannot change it.
        assert!(
            refused(Some(&identity("dedens", Some("ssl"))), dedens).contains("started as root")
        );
    }

    /// D122: the capabilities of a `/proc/PID/status` are the permitted, effective and ambient masks, all of them.
    #[test]
    fn capabilities_are_read_from_the_status() {
        let status = |permitted: &str, effective: &str, ambient: &str| {
            format!(
                "Uid:\t990\t990\t990\t990\nCapPrm:\t{permitted}\nCapEff:\t{effective}\nCapAmb:\t{ambient}\n"
            )
        };
        let none = "0000000000000000";
        assert!(Caps::read(&status(none, none, none)).none());
        assert!(!Caps::read(&status(none, "0000000000000400", none)).none());
        // Kept in the permitted set, a capability can be raised again: it counts.
        assert!(!Caps::read(&status("000001ffffffffff", none, none)).none());
        assert!(!Caps::read(&status(none, none, "0000000000000400")).none());
        assert_eq!(
            Caps::read(&status("1", "2", "3")),
            Caps {
                permitted: 1,
                effective: 2,
                ambient: 3
            }
        );
        let caps = Caps::read(&status("1", "2", "3"));
        assert_eq!(
            [caps.permitted(), caps.effective(), caps.ambient()],
            ["0000000000000001", "0000000000000002", "0000000000000003"]
        );
        // Unreadable is not a capability: the check is a belt, `setuid(0)` failing is the proof.
        assert!(Caps::read("Uid:\t990\n").none());
        assert_eq!(field("CapEff:\t0000\nCapPrm:\t1\n", "CapPrm"), Some("1"));
    }

    /// D122: a process with a second thread is refused, one that cannot be read is not.
    #[test]
    fn a_second_thread_is_seen() {
        assert!(alone("Name:\tdedensd\nThreads:\t1\n"));
        assert!(!alone("Name:\tdedensd\nThreads:\t3\n"));
        assert!(alone("Name:\tdedensd\n"));
    }
}
