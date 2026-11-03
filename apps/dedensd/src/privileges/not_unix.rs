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
