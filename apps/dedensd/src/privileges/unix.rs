//! The calls of Unix (D122): `nix`, safe wrappers of libc, so this crate keeps no `unsafe` of its own.

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

/// The real, effective and saved user ids, and the group ids, of the process; off Linux there is no saved id to
/// read, the effective one stands for it. One function for both, so that the tests on Linux reach its mutants.
#[cfg_attr(
    not(target_os = "linux"),
    expect(clippy::unnecessary_wraps, reason = "the signature of the Linux one")
)]
fn resolved() -> anyhow::Result<([u32; 3], [u32; 3])> {
    #[cfg(target_os = "linux")]
    let ids = {
        let uid = nix::unistd::getresuid().context("getresuid")?;
        let gid = nix::unistd::getresgid().context("getresgid")?;
        (
            [uid.real, uid.effective, uid.saved].map(Uid::as_raw),
            [gid.real, gid.effective, gid.saved].map(Gid::as_raw),
        )
    };
    #[cfg(not(target_os = "linux"))]
    let ids = {
        let uid = [nix::unistd::getuid(), nix::unistd::geteuid()].map(Uid::as_raw);
        let gid = [nix::unistd::getgid(), nix::unistd::getegid()].map(Gid::as_raw);
        ([uid[0], uid[1], uid[1]], [gid[0], gid[1], gid[1]])
    };
    Ok(ids)
}

/// The supplementary groups of the process; none off Linux, where `nix` does not have `getgroups` on every OS.
/// One function for both, as [`resolved`].
#[cfg_attr(
    not(target_os = "linux"),
    expect(clippy::unnecessary_wraps, reason = "the signature of the Linux one")
)]
fn supplementary() -> anyhow::Result<Vec<Gid>> {
    #[cfg(target_os = "linux")]
    let groups = nix::unistd::getgroups().context("getgroups")?;
    #[cfg(not(target_os = "linux"))]
    let groups = Vec::new();
    Ok(groups)
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
    effective(uid, gid)
}

/// [`ids`] of the real, effective and saved user ids `uid` and group ids `gid`.
fn effective(uid: [u32; 3], gid: [u32; 3]) -> anyhow::Result<Ids> {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::privileges::field;
    use crate::privileges::{Plan, apply};

    /// D122: the process is who its effective ids say; one that is not root must have one id of each kind, root may
    /// have others: it can become anyone.
    #[test]
    fn the_ids_must_agree_unless_root() {
        let me = Ids {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        };
        assert_eq!(ids().unwrap(), me);
        let dedens = Ids { uid: 990, gid: 990 };
        assert_eq!(effective([990; 3], [990; 3]).unwrap(), dedens);
        assert_eq!(
            effective([1000, 0, 1000], [5, 990, 7]).unwrap(),
            Ids { uid: 0, gid: 990 }
        );
        for (uid, gid) in [
            ([990, 990, 0], [990; 3]),
            ([0, 990, 990], [990; 3]),
            ([990; 3], [990, 990, 0]),
        ] {
            let error = effective(uid, gid).unwrap_err();
            assert!(
                error.to_string().contains("ids of the process differ"),
                "{error}"
            );
        }
    }

    /// D122: the process is in its own group and in its supplementary ones, as `/proc` lists them, and in no other.
    #[test]
    fn the_process_is_in_its_groups_only() {
        let own = nix::unistd::getegid().as_raw();
        assert!(in_group(own));
        #[cfg(target_os = "linux")]
        let held = {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let held: Vec<u32> = field(&status, "Groups")
                .unwrap()
                .split_whitespace()
                .map(|gid| gid.parse().unwrap())
                .collect();
            let supplementary = supplementary().unwrap();
            assert_eq!(
                supplementary
                    .into_iter()
                    .map(nix::unistd::Gid::as_raw)
                    .collect::<Vec<_>>(),
                held
            );
            held
        };
        #[cfg(not(target_os = "linux"))]
        let held = Vec::new();
        for gid in &held {
            assert!(in_group(*gid), "{gid}");
        }
        let other = (1..u32::MAX)
            .find(|gid| *gid != own && !held.contains(gid))
            .unwrap();
        assert!(!in_group(other), "{other}");
    }

    /// D122: sealing and dropping are refused from a second thread, before anything changes: the threads started
    /// before would keep the privileges.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_second_thread_refuses_the_seal_and_the_drop() {
        let me = ids().unwrap();
        let member = Member {
            uid: me.uid,
            entry: None,
        };
        let (stop, wait) = std::sync::mpsc::channel::<()>();
        std::thread::scope(|scope| {
            scope.spawn(move || wait.recv());
            for error in [
                apply(Plan::Already, None).unwrap_err(),
                drop_to(&member, me.gid).unwrap_err(),
            ] {
                assert!(
                    error.to_string().contains("more than one thread"),
                    "{error}"
                );
            }
            drop(stop);
        });
    }

    /// D122: `NO_NEW_PRIVS` is set, as the kernel reads it back; any process may set it on itself.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_new_privileges_is_set() {
        no_new_privs().unwrap();
        assert!(nix::sys::prctl::get_no_new_privs().unwrap());
    }

    /// D122: a downloads directory that cannot be made is an error, one that exists is not; the drop stops there.
    #[test]
    fn a_downloads_directory_that_cannot_be_made_stops_the_drop() {
        let root = tempfile::tempdir().unwrap();
        // Longer than a file name may be, even for root.
        let dir = root.path().join("d".repeat(300));
        let me = ids().unwrap();
        let error = prepare(&dir, me.uid, me.gid).unwrap_err();
        assert!(error.to_string().starts_with("cannot give"), "{error}");
        let plan = Plan::Drop {
            user: Member {
                uid: me.uid,
                entry: None,
            },
            gid: me.gid,
        };
        let error = apply(plan, Some(&dir)).unwrap_err();
        assert!(error.to_string().starts_with("cannot give"), "{error}");
    }

    /// D122: a directory that exists is left as it is, one that is missing is made, 0755.
    #[test]
    fn a_missing_downloads_directory_is_made_and_an_existing_one_kept() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let kept = root.path().join("kept");
        std::fs::create_dir(&kept).unwrap();
        let owner = std::fs::metadata(&kept).unwrap().uid();
        // Not given to anybody: it was there, and `lchown` to another user would fail unless root.
        prepare(&kept, u32::MAX - 1, u32::MAX - 1).unwrap();
        assert_eq!(std::fs::metadata(&kept).unwrap().uid(), owner);
        let me = ids().unwrap();
        let made = root.path().join("deep/made");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        prepare(&made, me.uid, me.gid).unwrap();
        let metadata = std::fs::metadata(&made).unwrap();
        assert!(metadata.is_dir());
        // The mode is the builder's, whatever the umask lets through.
        assert_eq!(metadata.mode() & 0o777 & !0o755, 0);
        assert_eq!((metadata.uid(), metadata.gid()), (me.uid, me.gid));
        // A symlink in its place is not followed.
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&kept, &link).unwrap();
        prepare(&link, u32::MAX - 1, u32::MAX - 1).unwrap();
        assert_eq!(std::fs::metadata(&kept).unwrap().uid(), owner);
    }
}
