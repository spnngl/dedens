//! The `access` section (D91): the networks a query may come from, read into an [`Access`], and the warning
//! when the server is open to all.

use dedens_server::{Access, Denial, Network};
use serde::Deserialize;

use super::Config;
use super::listen::Listen;

/// The access lists, as written (D91).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccessFile {
    /// Networks answered; none answers nobody.
    #[serde(default)]
    allow: Vec<Network>,
    /// Networks refused, inside an allowed one or not.
    #[serde(default)]
    deny: Vec<Network>,
    /// What a denied client gets.
    #[serde(default)]
    action: Denial,
}

impl AccessFile {
    pub(super) fn into_access(self) -> Access {
        Access::new(self.allow, self.deny, self.action)
    }
}

/// Where the access lists of a configuration come from (D91).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AccessSource {
    /// `access` is left out: only the local networks are answered.
    Unset,
    /// `access` allows some networks.
    Written,
    /// `access` allows no network: nobody is answered.
    NoAllow,
}

impl AccessSource {
    /// Where `access`, as written or left out, comes from.
    pub(super) fn of(access: Option<&AccessFile>) -> Self {
        match access {
            None => Self::Unset,
            Some(access) if access.allow.is_empty() => Self::NoAllow,
            Some(_) => Self::Written,
        }
    }
}

impl Config {
    /// Warns of access lists that answer little or nothing, for a server on `listen`: unset lists on a listen
    /// address outside the local networks (a wildcard address listens on every interface, public ones included),
    /// and written ones allowing nothing.
    pub(crate) fn warn_access(&self, listen: &[Listen]) {
        match self.access {
            AccessSource::Unset => {
                let local = Access::local(Denial::default());
                for listen in listen.iter().filter(|l| !local.permits(l.addr().ip())) {
                    tracing::warn!(
                        ?listen,
                        "no `access` configured: only loopback, private and link-local clients are answered (D91)"
                    );
                }
            }
            AccessSource::NoAllow => {
                tracing::warn!("`access` allows no network: no client is answered (D91)");
            }
            AccessSource::Written => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use dedens_server::Pipeline;

    use super::*;
    use crate::config::tests::*;

    /// D91: `access` is optional, and its lists and action read; what does not read is refused with the network
    /// meant.
    #[test]
    fn access_reads() {
        let with = |access: &str| format!("access:\n  {access}\n{MINIMAL}");
        let source = |text: &str| read(text, env, &Pipeline::default()).unwrap().access;
        assert_eq!(source(MINIMAL), AccessSource::Unset);
        for (access, expected) in [
            (
                "allow: ['10.0.0.0/8', '2001:db8::/32']",
                AccessSource::Written,
            ),
            ("allow: ['::/0']", AccessSource::Written),
            (
                "allow: []\n  deny: ['10.9.0.0/16']\n  action: drop",
                AccessSource::NoAllow,
            ),
            ("{}", AccessSource::NoAllow),
        ] {
            assert_eq!(source(&with(access)), expected, "{access}");
        }
        for (access, error) in [
            ("allow: ['192.0.2.1/24']", "`192.0.2.0/24`"),
            (
                "deny: ['192.0.2.0/24', 'nope']",
                "`nope` is not ADDRESS/LENGTH",
            ),
            ("action: Drop", "unknown variant `Drop`"),
            ("allow: '10.0.0.0/8'", "expected sequence"),
        ] {
            let refused = read(&with(access), env, &Pipeline::default()).unwrap_err();
            assert!(
                format!("{refused:#}").contains(error),
                "{access}: {refused:#}"
            );
        }
    }
}
