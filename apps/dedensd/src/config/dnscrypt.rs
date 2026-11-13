//! The `dnscrypt` section (D99): the provider `dedensd` serves `DNSCrypt` as, and the file with its key.

use std::path::PathBuf;

use serde::Deserialize;

/// The `DNSCrypt` resolver `dedensd` serves as, behind each `dnscrypt://` address of `listen`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DnscryptFile {
    /// The name clients ask the certificates under: `2.dnscrypt-cert.` and a domain.
    provider_name: String,
    /// A file with the provider's `Ed25519` seed, 64 hexadecimal digits: `dedensd dnscrypt-keygen` makes one.
    secret_key: PathBuf,
    /// The encryption systems offered. Default: both.
    systems: Option<Vec<SystemFile>>,
}

/// An encryption system as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SystemFile {
    /// `X25519-XSalsa20Poly1305`, `<es-version>` 0x0001.
    Xsalsa20,
    /// `X25519-XChaCha20Poly1305`, `<es-version>` 0x0002.
    Xchacha20,
}

/// The first labels of a provider name (draft "Certificates": the certificate query's name is `<version>.dnscrypt-cert.`
/// and the provider's domain, version 2 for the protocol's current one).
#[cfg(feature = "dnscrypt")]
const PROVIDER_PREFIX: &str = "2.dnscrypt-cert.";

/// The provider name `name`, which a stamp holds.
///
/// # Errors
///
/// A name that does not start with `2.dnscrypt-cert.`, or that a stamp cannot hold.
#[cfg(feature = "dnscrypt")]
pub(crate) fn provider(name: &str) -> anyhow::Result<dedens_net::stamp::ProviderName> {
    use anyhow::{Context as _, ensure};

    ensure!(
        name.get(..PROVIDER_PREFIX.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(PROVIDER_PREFIX)),
        "provider name {name:?} does not start with `{PROVIDER_PREFIX}`"
    );
    name.parse()
        .with_context(|| format!("provider name {name:?}"))
}

/// The resolver `dnscrypt` describes, if any (D99).
///
/// # Errors
///
/// A `dnscrypt://` address in `listen` without a section, a section without such an address, a provider name that
/// does not start with `2.dnscrypt-cert.` or is not one a stamp can hold, a system listed twice or none, or a
/// `dnscrypt://` address on the port of another listener. The key is not read: [`crate::dnscrypt::Section::service`]
/// does, at start.
#[cfg(feature = "dnscrypt")]
pub(super) fn section(
    dnscrypt: Option<&DnscryptFile>,
    listen: &[super::Listen],
) -> anyhow::Result<Option<crate::dnscrypt::Section>> {
    use anyhow::{Context as _, ensure};
    use dedens_dnscrypt::EncryptionSystem;

    let serving = listen
        .iter()
        .any(|listen| matches!(listen, super::Listen::Dnscrypt(_)));
    let Some(file) = dnscrypt else {
        ensure!(
            !serving,
            "`listen` has a dnscrypt:// address, and there is no `dnscrypt` section"
        );
        return Ok(None);
    };
    ensure!(
        serving,
        "`dnscrypt` is set, and `listen` has no dnscrypt:// address"
    );
    super::listen::distinct_ports(listen)?;
    let provider = provider(&file.provider_name).context("`dnscrypt`: `provider_name`")?;
    let named = file
        .systems
        .as_deref()
        .unwrap_or(&[SystemFile::Xchacha20, SystemFile::Xsalsa20]);
    ensure!(!named.is_empty(), "`dnscrypt`: `systems` is empty");
    let mut systems = Vec::new();
    for system in named {
        let system = match system {
            SystemFile::Xsalsa20 => EncryptionSystem::XSalsa20Poly1305,
            SystemFile::Xchacha20 => EncryptionSystem::XChaCha20Poly1305,
        };
        ensure!(
            !systems.contains(&system),
            "`dnscrypt`: `systems` lists {system:?} twice"
        );
        systems.push(system);
    }
    Ok(Some(crate::dnscrypt::Section {
        provider,
        key: file.secret_key.clone(),
        systems,
    }))
}

#[cfg(all(test, feature = "dnscrypt"))]
mod tests {
    use dedens_dnscrypt::EncryptionSystem;
    use dedens_server::Pipeline;

    use crate::config::tests::*;
    use crate::config::{Config, Listen};

    const SECTION: &str = "dnscrypt:\n  provider_name: 2.dnscrypt-cert.example.net\n  secret_key: /nonexistent/dnscrypt.key\n";

    fn config(listen: &str, dnscrypt: &str) -> anyhow::Result<Config> {
        let text = format!(
            "listen: [{listen}]\n{dnscrypt}pipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
        );
        read(&text, env, &Pipeline::default())
    }

    fn refused(listen: &str, dnscrypt: &str) -> String {
        format!("{:#}", config(listen, dnscrypt).expect_err("refused"))
    }

    fn section(dnscrypt: &str) -> crate::dnscrypt::Section {
        config("'dnscrypt://127.0.0.1:8443'", dnscrypt)
            .expect("read")
            .dnscrypt
            .expect("a section")
    }

    /// The section reads, with both systems unless set, the key not opened.
    #[test]
    fn the_section_reads_with_both_systems_by_default() {
        let config = config("'dnscrypt://127.0.0.1', '127.0.0.1:5353'", SECTION).unwrap();
        assert_eq!(
            config.listen[0],
            Listen::Dnscrypt("127.0.0.1:443".parse().unwrap())
        );
        let both = config.dnscrypt.unwrap();
        assert_eq!(both.provider.to_string(), "2.dnscrypt-cert.example.net");
        assert_eq!(both.key.to_str(), Some("/nonexistent/dnscrypt.key"));
        assert_eq!(
            both.systems,
            [
                EncryptionSystem::XChaCha20Poly1305,
                EncryptionSystem::XSalsa20Poly1305
            ]
        );
        let one = section(&format!("{SECTION}  systems: [xsalsa20]\n"));
        assert_eq!(one.systems, [EncryptionSystem::XSalsa20Poly1305]);
        // The prefix is matched whatever its case.
        let upper = section(&SECTION.replace("2.dnscrypt-cert", "2.DNSCrypt-Cert"));
        assert!(
            upper
                .provider
                .to_string()
                .eq_ignore_ascii_case("2.dnscrypt-cert.example.net")
        );
    }

    #[test]
    fn what_cannot_serve_is_refused() {
        let listen = "'dnscrypt://127.0.0.1'";
        assert!(refused(listen, "").contains("no `dnscrypt` section"));
        assert!(refused("'127.0.0.1:53'", SECTION).contains("no dnscrypt:// address"));
        let name =
            |name: &str| SECTION.replace("2.dnscrypt-cert.example.net", &format!("'{name}'"));
        for bad in [
            "example.net",
            "1.dnscrypt-cert.example.net",
            "2.dnscrypt-cert",
            "",
        ] {
            assert!(
                refused(listen, &name(bad)).contains("`provider_name`"),
                "{bad:?}"
            );
        }
        assert!(
            refused(listen, &format!("{SECTION}  systems: [aes]\n")).contains("unknown variant")
        );
        assert!(refused(listen, &format!("{SECTION}  systems: []\n")).contains("is empty"));
        assert!(
            refused(
                listen,
                &format!("{SECTION}  systems: [xsalsa20, xsalsa20]\n")
            )
            .contains("twice")
        );
        let no_key = "dnscrypt:\n  provider_name: 2.dnscrypt-cert.example.net\n";
        assert!(refused(listen, no_key).contains("secret_key"));
        let unknown = format!("{SECTION}  key: x\n");
        assert!(refused(listen, &unknown).contains("unknown field"));
        assert!(refused("'dnscrypt://dns.example'", SECTION).contains("dnscrypt://"));
    }

    /// A `dnscrypt://` address takes UDP and TCP on its port: no other listener takes either on the same address.
    #[test]
    fn a_port_is_not_shared() {
        for other in ["'127.0.0.1:443'", "'dnscrypt://127.0.0.1:443'"] {
            let listen = format!("'dnscrypt://127.0.0.1', {other}");
            let message = refused(&listen, SECTION);
            assert!(message.contains("take the same port"), "{other}: {message}");
        }
        // Another port, or another address, is fine.
        for other in [
            "'127.0.0.1:53'",
            "'dnscrypt://127.0.0.2'",
            "'dnscrypt://127.0.0.1:8443'",
        ] {
            config(&format!("'dnscrypt://127.0.0.1', {other}"), SECTION).unwrap();
        }
    }
}
