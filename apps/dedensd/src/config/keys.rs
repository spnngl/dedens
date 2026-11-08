//! Secrets and trust (D115): the `odoh` section and the target's key (D79, D94, D117), the permissions of a key
//! file, and the certificate authorities upstream servers are checked against.

use std::fs;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use compio::rustls::pki_types::CertificateDer;
use compio::rustls::pki_types::pem::PemObject as _;
use dedens_net::tls::Trust;
use serde::Deserialize;

use super::limits::BudgetFile;
#[cfg(feature = "odoh")]
use super::listen::Listen;

/// The Oblivious `DoH` target `dedensd` serves as (D79).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OdohFile {
    /// A file with the target's secret, 64 hexadecimal digits. Default: a new random secret at each start.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the target, built with the odoh feature")
    )]
    key: Option<PathBuf>,
    /// Forwarding queries to other targets too (D94).
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the proxy, built with the odoh feature")
    )]
    proxy: Option<ProxyFile>,
    /// What all clients may open together: `rate` decapsulations a second and `burst` at once, 10 000 and 20 000
    /// by default (D117); past them, 503 before the request is parsed or opened.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the target, built with the odoh feature")
    )]
    budget: Option<BudgetFile>,
    /// What a client network may open, as `dedensd` sees it (a proxy's, D91): `rate` a second and `burst` at once,
    /// 1000 and 2000 by default (D117); past them, 503 before the request is parsed or opened. Sources on the
    /// `rrl.exempt` list (D113) have none.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the target, built with the odoh feature")
    )]
    client_budget: Option<BudgetFile>,
}

/// The Oblivious `DoH` proxy `dedensd` serves as (D94).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyFile {
    /// The targets forwarded to, `HOST[:PORT]` each: any other is refused.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the proxy, built with the odoh feature")
    )]
    targets: Vec<String>,
    /// How long a forward may take, in milliseconds. Default: 5000.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the proxy, built with the odoh feature")
    )]
    timeout_ms: Option<NonZeroU32>,
}

/// The Oblivious `DoH` target settings of `odoh`, if any (D79, D94). The key is not read: a reload builds this again,
/// and the key is read at start (D79).
///
/// # Errors
///
/// `odoh` without an `https://` address in `listen`, or a proxy without a target or with one that is not `HOST[:PORT]`.
#[cfg(feature = "odoh")]
pub(super) fn section(
    odoh: Option<&OdohFile>,
    listen: &[Listen],
) -> anyhow::Result<Option<crate::odoh::Section>> {
    let Some(odoh) = odoh else {
        return Ok(None);
    };
    ensure!(
        listen
            .iter()
            .any(|listen| matches!(listen, Listen::Https(..))),
        "`odoh` is served over HTTP/3: `listen` has no https:// address"
    );
    let proxy = odoh
        .proxy
        .as_ref()
        .map(|proxy| crate::odoh::proxy::Settings::new(&proxy.targets, proxy.timeout_ms))
        .transpose()?;
    let default = crate::odoh::Limits::default();
    let limits = crate::odoh::Limits {
        client: BudgetFile::over(odoh.client_budget, default.client),
        global: BudgetFile::over(odoh.budget, default.global),
    };
    Ok(Some(crate::odoh::Section::new(
        odoh.key.as_deref(),
        proxy,
        limits,
    )))
}

/// Checks the private key file `file`, opened from `path` for `setting` (`tls` or `odoh`), on the file itself, so that
/// no swap of the path comes between the check and the read: the key stays unused when others can access it, and
/// is warned about when its group can (D115). `ssh` and PostgreSQL refuse a key others can access; the group is
/// allowed, as PostgreSQL allows a root-owned key its group: quietly for a root-owned key whose group the process is
/// in (`root:dedens` 0640 read by the user `dedens` after the drop of D122, which is read again as that user, or a key
/// shared through Debian's `ssl-cert`), with a warning otherwise. A process that is root is in no such group, and
/// reads any key: a root-owned key is not warned about then, the read after the drop is the check. Off Unix, where
/// the mode says nothing, nothing is checked.
///
/// # Errors
///
/// A mode that cannot be read, or any permission for others.
#[cfg(unix)]
pub(crate) fn guard_key(file: &fs::File, setting: &str, path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    use nix::unistd::geteuid;
    let shown = path.display();
    let metadata = file
        .metadata()
        .with_context(|| format!("{setting}: cannot read the key {shown}"))?;
    let mode = metadata.mode() & 0o777;
    let (group, others) = (mode & 0o070, mode & 0o007);
    ensure!(
        others == 0,
        "{setting}: the key {shown} can be accessed by others (mode {mode:03o}): chmod 600"
    );
    let shared = shared_key(metadata.uid(), geteuid().is_root(), || {
        crate::privileges::in_group(metadata.gid())
    });
    if group != 0 && !shared {
        tracing::warn!(key = %shown, mode = format!("{mode:03o}"), "{setting}: the key can be accessed by its group: chmod 600 unless the group is meant to");
    }
    Ok(())
}

/// Whether [`guard_key`] lets a key of `owner` be read by its group quietly: root owns it, and the process is root
/// or, as `member` says, in its group.
#[cfg(unix)]
fn shared_key(owner: u32, root: bool, member: impl FnOnce() -> bool) -> bool {
    owner == 0 && (root || member())
}

/// [`guard_key`] off Unix: nothing to check.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "the signature of the Unix one")]
pub(crate) fn guard_key(_file: &fs::File, _setting: &str, _path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// The certificate authorities of the PEM file `path`, the system's without one.
///
/// # Errors
///
/// A file that does not read, or holds no certificate.
pub(super) fn trusted(path: Option<&Path>) -> anyhow::Result<Trust> {
    let Some(path) = path else {
        return Ok(Trust::System);
    };
    let certificates = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| {
            format!(
                "`upstream_ca`: cannot read certificates from {}",
                path.display()
            )
        })?;
    ensure!(
        !certificates.is_empty(),
        "`upstream_ca`: no certificate in {}",
        path.display()
    );
    Ok(Trust::Roots(certificates))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "odoh")]
    use dedens_server::Budget;
    use dedens_server::Pipeline;

    use super::*;
    use crate::config::tests::*;

    #[test]
    fn upstream_certificate_authorities_are_read() {
        let refused = read(
            &format!("upstream_ca: /nonexistent.pem\n{MINIMAL}"),
            env,
            &Pipeline::default(),
        );
        assert!(refused.unwrap_err().to_string().contains("`upstream_ca`"));
        assert_eq!(
            read(MINIMAL, env, &Pipeline::default()).unwrap().trust,
            Trust::System
        );
    }

    /// `odoh` needs an `https://` address and a dedensd built for it, and takes a `key` and nothing else (D79).
    #[test]
    fn odoh_needs_an_https_listener() {
        let odoh = |section: &str| format!("odoh:\n{section}{MINIMAL}");
        let error = read(&odoh("  key: /nonexistent\n"), env, &Pipeline::default()).unwrap_err();
        let message = format!("{error:#}");
        #[cfg(feature = "odoh")]
        assert!(
            message.contains("`listen` has no https:// address"),
            "{message}"
        );
        #[cfg(not(feature = "odoh"))]
        assert!(message.contains("built with the odoh feature"), "{message}");
        let error = read(&odoh("  keys: 1\n"), env, &Pipeline::default()).unwrap_err();
        assert!(format!("{error:#}").contains("keys"), "{error:#}");
        let error = read(
            &odoh("  proxy:\n    target: 1\n"),
            env,
            &Pipeline::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("target"), "{error:#}");
    }

    /// A proxy lists the targets it forwards to, `HOST[:PORT]` each, and at least one (D94).
    #[cfg(feature = "odoh")]
    #[test]
    fn a_proxy_needs_targets() {
        let listen = [Listen::Https(
            "127.0.0.1:443".parse().unwrap(),
            "/dns-query".into(),
        )];
        let section = |text: &str| {
            let odoh: OdohFile = serde_saphyr::from_str(text).unwrap();
            section(Some(&odoh), &listen)
        };
        assert!(
            section("proxy:\n  targets: [odoh.example, '127.0.0.1:8443']\n  timeout_ms: 100\n")
                .is_ok()
        );
        assert!(section("key: /a\n").is_ok());
        for bad in [
            "proxy:\n  targets: []\n",
            "proxy:\n  targets: ['a b']\n",
            "proxy:\n  targets: ['a:0']\n",
        ] {
            assert!(section(bad).is_err(), "{bad}");
        }
        assert!(serde_saphyr::from_str::<OdohFile>("proxy:\n  timeout_ms: 100\n").is_err());
    }

    /// D117: the target's limits are the defaults unless `budget` and `client_budget` say; zero is refused.
    #[cfg(feature = "odoh")]
    #[test]
    fn an_odoh_target_has_limits() {
        let listen = [Listen::Https(
            "127.0.0.1:443".parse().unwrap(),
            "/dns-query".into(),
        )];
        let section = |text: &str| {
            let odoh: OdohFile = serde_saphyr::from_str(text).unwrap();
            section(Some(&odoh), &listen).unwrap().unwrap()
        };
        let default = crate::odoh::Section::new(None, None, crate::odoh::Limits::default());
        assert_eq!(section("{}"), default);
        let defaults = crate::odoh::Limits::default();
        let limits = crate::odoh::Limits {
            client: Budget {
                per_second: 10,
                burst: 20,
                table: defaults.client.table,
            },
            global: Budget {
                per_second: 99,
                ..defaults.global
            },
        };
        assert_eq!(
            section("budget: {rate: 99}\nclient_budget: {rate: 10, burst: 20}\n"),
            crate::odoh::Section::new(None, None, limits)
        );
        // A reload compares sections, and warns that a change of `odoh` takes a restart: the limits are part of it.
        assert_ne!(section("client_budget: {rate: 10}\n"), default);
        assert_ne!(section("budget: {rate: 10}\n"), default);
        for bad in ["budget: {burst: 0}\n", "client_budget: {rate: 0}\n"] {
            assert!(serde_saphyr::from_str::<OdohFile>(bad).is_err(), "{bad}");
        }
    }

    /// D115: a key its group can read is quiet when root owns it and the process is root or in its group.
    #[cfg(unix)]
    #[test]
    fn a_key_is_shared_with_its_group_when_root_owns_it() {
        assert!(shared_key(0, true, || false));
        assert!(shared_key(0, false, || true));
        assert!(!shared_key(0, false, || false));
        assert!(!shared_key(1000, true, || true));
    }
}
