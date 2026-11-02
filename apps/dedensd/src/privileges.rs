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

#[cfg(unix)]
mod os {
    //! The calls: `nix`, safe wrappers of libc, so this crate keeps no `unsafe` of its own.

    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::Path;

    use anyhow::{Context, ensure};
    use nix::unistd::{Gid, Group, Uid, User, setgid, setuid};

    use super::{Account, Accounts, Caps, Entry, Ids, Member, alone};

    /// The system's users and groups.
    #[derive(Debug)]
    pub(crate) struct System;

    impl Accounts for System {
        fn user(&self, account: &Account) -> anyhow::Result<Member> {
            let member = |user: User| Member {
                uid: user.uid.as_raw(),
                entry: Some(Entry {
                    name: user.name,
                    gid: user.gid.as_raw(),
                }),
            };
            match account {
                Account::Name(name) => Ok(member(
                    User::from_name(name)
                        .with_context(|| format!("cannot look up the user {name}"))?
                        .with_context(|| format!("no user named {name}"))?,
                )),
                // An id with no entry is still an id: a service account kept out of `/etc/passwd`.
                Account::Id(id) => Ok(User::from_uid(Uid::from_raw(*id))
                    .with_context(|| format!("cannot look up the user {id}"))?
                    .map_or(
                        Member {
                            uid: *id,
                            entry: None,
                        },
                        member,
                    )),
            }
        }

        fn group(&self, account: &Account) -> anyhow::Result<u32> {
            match account {
                Account::Name(name) => Ok(Group::from_name(name)
                    .with_context(|| format!("cannot look up the group {name}"))?
                    .with_context(|| format!("no group named {name}"))?
                    .gid
                    .as_raw()),
                Account::Id(id) => Ok(*id),
            }
        }
    }

    /// The real, effective and saved user ids, and the group ids, of the process.
    #[cfg(target_os = "linux")]
    fn resolved() -> anyhow::Result<([u32; 3], [u32; 3])> {
        let uid = nix::unistd::getresuid().context("getresuid")?;
        let gid = nix::unistd::getresgid().context("getresgid")?;
        Ok((
            [uid.real, uid.effective, uid.saved].map(Uid::as_raw),
            [gid.real, gid.effective, gid.saved].map(Gid::as_raw),
        ))
    }

    /// Off Linux there is no saved id to read: the real and the effective ones.
    #[cfg(not(target_os = "linux"))]
    #[expect(clippy::unnecessary_wraps, reason = "the signature of the Linux one")]
    fn resolved() -> anyhow::Result<([u32; 3], [u32; 3])> {
        let uid = [nix::unistd::getuid(), nix::unistd::geteuid()].map(Uid::as_raw);
        let gid = [nix::unistd::getgid(), nix::unistd::getegid()].map(Gid::as_raw);
        Ok(([uid[0], uid[1], uid[1]], [gid[0], gid[1], gid[1]]))
    }

    /// The supplementary groups of the process; none off Linux, where `nix` does not have `getgroups` on every OS.
    #[cfg(target_os = "linux")]
    fn supplementary() -> anyhow::Result<Vec<Gid>> {
        nix::unistd::getgroups().context("getgroups")
    }

    #[cfg(not(target_os = "linux"))]
    #[expect(clippy::unnecessary_wraps, reason = "the signature of the Linux one")]
    fn supplementary() -> anyhow::Result<Vec<Gid>> {
        Ok(Vec::new())
    }

    /// Whether the process is in the group `gid`, as its own or a supplementary one.
    pub(crate) fn in_group(gid: u32) -> bool {
        let gid = Gid::from_raw(gid);
        nix::unistd::getegid() == gid || supplementary().is_ok_and(|groups| groups.contains(&gid))
    }

    /// Who the process runs as, by its effective ids.
    ///
    /// # Errors
    ///
    /// A process that is not root and whose real, effective and saved ids differ: one of them may be root, which it
    /// can go back to.
    pub(crate) fn ids() -> anyhow::Result<Ids> {
        let (uid, gid) = resolved()?;
        if uid[1] != 0 {
            ensure!(
                uid.iter().all(|id| *id == uid[1]) && gid.iter().all(|id| *id == gid[1]),
                "the real, effective and saved ids of the process differ (uids {uid:?}, gids {gid:?}): start it as the user, or as root"
            );
        }
        Ok(Ids {
            uid: uid[1],
            gid: gid[1],
        })
    }

    /// Creates the downloads directory `dir` if it is missing, mode 0755, and gives it to `uid` and `gid`: the user
    /// that serves writes the lists it downloads there (D104). A directory that exists is left as it is, whoever
    /// owns it: a wrong path would hand the user `/etc`. The ownership is set on the path itself (`lchown`), not on
    /// what a swapped link points to.
    pub(super) fn prepare(dir: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        match std::fs::DirBuilder::new().mode(0o755).create(dir) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            made => made
                .and_then(|()| std::os::unix::fs::lchown(dir, Some(uid), Some(gid)))
                .with_context(|| format!("cannot give {} to uid {uid}", dir.display())),
        }
    }

    /// The capabilities of the process, and an error for a second thread: `NO_NEW_PRIVS` is set by, and inherited
    /// by the threads started after, the one that sets it.
    fn thread_and_caps() -> anyhow::Result<Caps> {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        ensure!(
            alone(&status),
            "the process has more than one thread: privileges drop before the first one starts"
        );
        Ok(Caps::read(&status))
    }

    /// Sets `PR_SET_NO_NEW_PRIVS` and reads it back, where the OS has it.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(clippy::unnecessary_wraps, reason = "the signature of the Linux one")
    )]
    fn no_new_privs() -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            nix::sys::prctl::set_no_new_privs().context("PR_SET_NO_NEW_PRIVS")?;
            ensure!(
                nix::sys::prctl::get_no_new_privs().context("PR_GET_NO_NEW_PRIVS")?,
                "no_new_privs is not set"
            );
        }
        Ok(())
    }

    /// Keeps a process that is the user already from gaining privileges, and says what it holds.
    pub(super) fn seal() -> anyhow::Result<Caps> {
        let caps = thread_and_caps()?;
        no_new_privs()?;
        Ok(caps)
    }

    /// Becomes `member` of group `gid`, with no way back.
    pub(super) fn drop_to(member: &Member, gid: u32) -> anyhow::Result<()> {
        thread_and_caps()?;
        groups(member, gid)?;
        setgid(Gid::from_raw(gid)).context("setgid")?;
        setuid(Uid::from_raw(member.uid)).context("setuid")?;
        let (uid, gids) = resolved()?;
        ensure!(
            uid == [member.uid; 3] && gids == [gid; 3],
            "the process is uid {uid:?} and gid {gids:?} after the drop, not uid {} and gid {gid}",
            member.uid
        );
        ensure!(
            !supplementary()?.contains(&Gid::from_raw(0)),
            "the user is in the group root: remove it from `/etc/group`"
        );
        ensure!(
            setuid(Uid::from_raw(0)).is_err() && setgid(Gid::from_raw(0)).is_err(),
            "the process can still become root after the drop"
        );
        no_new_privs()?;
        // The kernel clears the capabilities with the user; `/proc` says it did, where it is mounted.
        ensure!(
            thread_and_caps()?.none(),
            "the process keeps a capability after the drop"
        );
        Ok(())
    }

    /// The groups of `member`: those that list it and `gid`, none for a user without an entry.
    #[cfg(target_os = "linux")]
    fn groups(member: &Member, gid: u32) -> anyhow::Result<()> {
        match &member.entry {
            Some(entry) => nix::unistd::initgroups(
                &std::ffi::CString::new(entry.name.as_str()).context("a user name with a NUL")?,
                Gid::from_raw(gid),
            ),
            None => nix::unistd::setgroups(&[]),
        }
        .context("setgroups")
    }

    /// Off Linux, `nix` has no calls for the groups of a process: `user` is refused when the configuration is read.
    #[cfg(not(target_os = "linux"))]
    fn groups(_member: &Member, _gid: u32) -> anyhow::Result<()> {
        anyhow::bail!("dropping privileges is Linux only")
    }
}

#[cfg(not(unix))]
mod os {
    //! No users to drop to: `user` is refused when the configuration is read.

    use std::path::Path;

    use super::{Account, Accounts, Caps, Ids, Member};

    #[derive(Debug)]
    pub(crate) struct System;

    impl Accounts for System {
        fn user(&self, _account: &Account) -> anyhow::Result<Member> {
            anyhow::bail!("no users here")
        }

        fn group(&self, _account: &Account) -> anyhow::Result<u32> {
            anyhow::bail!("no groups here")
        }
    }

    /// Nobody to be: not root.
    #[expect(clippy::unnecessary_wraps, reason = "the signature of the Unix one")]
    pub(crate) const fn ids() -> anyhow::Result<Ids> {
        Ok(Ids { uid: 1, gid: 1 })
    }

    /// No groups.
    pub(crate) const fn in_group(_gid: u32) -> bool {
        false
    }

    pub(super) fn prepare(_dir: &Path, _uid: u32, _gid: u32) -> anyhow::Result<()> {
        Ok(())
    }

    pub(super) fn seal() -> anyhow::Result<Caps> {
        Ok(Caps::default())
    }

    pub(super) fn drop_to(_member: &Member, _gid: u32) -> anyhow::Result<()> {
        anyhow::bail!("dropping privileges is Linux only")
    }
}

pub(crate) use os::{System, ids, in_group};

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
        assert_eq!(
            Caps::read(&status("1", "2", "3")).effective(),
            "0000000000000002"
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

    /// D122: a directory that exists is left as it is, one that is missing is made, 0755.
    #[cfg(unix)]
    #[test]
    fn a_missing_downloads_directory_is_made_and_an_existing_one_kept() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let kept = root.path().join("kept");
        std::fs::create_dir(&kept).unwrap();
        let owner = std::fs::metadata(&kept).unwrap().uid();
        // Not given to anybody: it was there, and `lchown` to another user would fail unless root.
        os::prepare(&kept, u32::MAX - 1, u32::MAX - 1).unwrap();
        assert_eq!(std::fs::metadata(&kept).unwrap().uid(), owner);
        let me = ids().unwrap();
        let made = root.path().join("deep/made");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        os::prepare(&made, me.uid, me.gid).unwrap();
        let metadata = std::fs::metadata(&made).unwrap();
        assert!(metadata.is_dir());
        // The mode is the builder's, whatever the umask lets through.
        assert_eq!(metadata.mode() & 0o777 & !0o755, 0);
        assert_eq!((metadata.uid(), metadata.gid()), (me.uid, me.gid));
        // A symlink in its place is not followed.
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&kept, &link).unwrap();
        os::prepare(&link, u32::MAX - 1, u32::MAX - 1).unwrap();
        assert_eq!(std::fs::metadata(&kept).unwrap().uid(), owner);
    }
}
