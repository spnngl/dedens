//! `dedensd` as an Oblivious `DoH` target (RFC 9230 §8, D79): the key, the configurations served for it, and the
//! opening of queries and sealing of replies; and the proxy role (D94), [`proxy`].

use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use dedens_net::odoh::{self, Entropy};
use dedens_odoh::{
    ExchangeError, ObliviousDoHConfigs, ObliviousDoHMessage, ResponseContext, TargetKey,
    decrypt_query, encrypt_response, response_padding,
};
use http::{Response, StatusCode};
use zeroize::Zeroizing;

use self::proxy::{Proxy, Settings as ProxySettings};

pub(crate) mod proxy;

/// How long clients may keep the configurations, in seconds (D79).
const CONFIGS_MAX_AGE: u32 = 3600;

/// The bytes of the secret a key derives from (D78).
const SECRET_LEN: usize = 32;

/// The settings of a target: where its secret comes from, and the proxy role if it has it. A reload builds them again
/// and compares: the secret is read at start only (D79), and so are the proxy's targets (D94).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    /// The file the secret is read from; `None` for one generated at start.
    key: Option<PathBuf>,
    /// The proxy role: what it forwards to; `None` for a target only.
    proxy: Option<ProxySettings>,
}

impl Section {
    pub(crate) fn new(key: Option<&Path>, proxy: Option<ProxySettings>) -> Self {
        Self {
            key: key.map(Path::to_path_buf),
            proxy,
        }
    }

    /// The target of the settings: reads the key.
    ///
    /// # Errors
    ///
    /// As [`Target::new`].
    pub(crate) fn target(&self) -> anyhow::Result<Target> {
        let target = Target::new(self.key.as_deref())?;
        Ok(match &self.proxy {
            Some(settings) => target.proxying(settings.clone()),
            None => target,
        })
    }
}

/// The key of a target and the configurations that go with it, and the proxy that shares its listeners (D94).
#[derive(Debug)]
pub(crate) struct Target {
    key: TargetKey,
    /// The encoded configurations (RFC 9230 §5), served at the well-known path.
    configs: Vec<u8>,
    /// Forwards the requests that name a target of their own; `None` when `dedensd` is no proxy.
    pub(crate) proxy: Option<Proxy>,
}

impl Target {
    /// The target of the secret in `file`: 64 hexadecimal digits, as `openssl rand -hex 32` writes them; a new
    /// random one when there is no file.
    ///
    /// # Errors
    ///
    /// A file that does not read or is not 64 hexadecimal digits, or no randomness.
    pub(crate) fn new(file: Option<&Path>) -> anyhow::Result<Self> {
        let secret = if let Some(file) = file {
            read_secret(file)?
        } else {
            let mut secret = Zeroizing::new([0; SECRET_LEN]);
            getrandom::fill(&mut *secret).context("`odoh`: no randomness for a key")?;
            secret
        };
        let key = TargetKey::derive(&secret);
        let configs = ObliviousDoHConfigs::new(vec![key.config().clone()])
            .encode()
            .context("`odoh`: the configurations do not encode")?;
        Ok(Self {
            key,
            configs,
            proxy: None,
        })
    }

    /// The target, forwarding too as `settings` say.
    fn proxying(self, settings: ProxySettings) -> Self {
        Self {
            proxy: Some(Proxy::new(settings)),
            ..self
        }
    }

    /// The response to a GET of the configurations.
    pub(crate) fn configs(&self) -> Response<Vec<u8>> {
        odoh::configs_response(self.configs.clone(), CONFIGS_MAX_AGE)
    }

    /// The DNS query in the body of a POST, and what it takes to seal its reply (RFC 9230 §8).
    ///
    /// # Errors
    ///
    /// 401 for a key identifier that is not this target's, so the client fetches the configurations again
    /// (§4.3); 400 for anything else that does not decrypt.
    pub(crate) fn open(&self, body: &[u8]) -> Result<(Vec<u8>, ResponseContext), StatusCode> {
        let message = ObliviousDoHMessage::parse(body).map_err(|_| StatusCode::BAD_REQUEST)?;
        match decrypt_query(&self.key, &message) {
            Ok((plaintext, context)) => Ok((plaintext.into_dns_message(), context)),
            Err(ExchangeError::UnknownKey) => Err(StatusCode::UNAUTHORIZED),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }
}

/// The response carrying `wire`, sealed and padded (RFC 9230 §6.2, §4.3); 500 when it cannot be sealed.
pub(crate) fn seal(context: ResponseContext, wire: &[u8]) -> Result<Response<Vec<u8>>, StatusCode> {
    let mut entropy = Entropy::new().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = encrypt_response(context, wire, response_padding(wire.len()), &mut entropy)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    entropy
        .finish()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(odoh::target_response(&message))
}

/// The most bytes a key file holds: [`SECRET_LEN`] bytes as digits and room for whitespace.
const KEY_FILE_MAX: usize = 4 * SECRET_LEN;

/// The secret in `file`: [`SECRET_LEN`] bytes as hexadecimal digits, surrounding whitespace aside. Read into a buffer
/// of its size, wiped on drop, so that no copy of the secret is left where a growing buffer was; a file group or
/// world readable is warned about.
fn read_secret(file: &Path) -> anyhow::Result<Zeroizing<[u8; SECRET_LEN]>> {
    let shown = file.display();
    let mut input =
        File::open(file).with_context(|| format!("`odoh`: cannot read the key {shown}"))?;
    if exposed(&input).with_context(|| format!("`odoh`: cannot read the key {shown}"))? {
        tracing::warn!(key = %shown, "`odoh`: the key is readable by others than its owner: chmod 600");
    }
    // One byte more than the most, to tell a file that is too long.
    let mut buffer = Zeroizing::new([0; KEY_FILE_MAX + 1]);
    let mut len = 0;
    while let Some(rest) = buffer.get_mut(len..).filter(|rest| !rest.is_empty()) {
        match input.read(rest) {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(error).with_context(|| format!("`odoh`: cannot read the key {shown}"));
            }
        }
    }
    ensure!(
        len <= KEY_FILE_MAX,
        "`odoh`: the key {shown} is longer than {KEY_FILE_MAX} bytes"
    );
    let text = buffer.get(..len).unwrap_or_default().trim_ascii();
    let (pairs, rest) = text.as_chunks::<2>();
    let mut secret = Zeroizing::new([0; SECRET_LEN]);
    ensure!(
        rest.is_empty() && pairs.len() == SECRET_LEN,
        "`odoh`: the key {shown} is not {} hexadecimal digits",
        2 * SECRET_LEN
    );
    for (byte, &[high, low]) in secret.iter_mut().zip(pairs) {
        let (Some(high), Some(low)) = (digit(high), digit(low)) else {
            bail!("`odoh`: the key {shown} has a character that is no hexadecimal digit");
        };
        *byte = high << 4 | low;
    }
    Ok(secret)
}

/// Whether `file` can be read or written by its group or by others.
#[cfg(unix)]
fn exposed(file: &File) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt as _;
    Ok(file.metadata()?.permissions().mode() & 0o077 != 0)
}

/// Whether `file` can be read or written by others than its owner: not known off Unix.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "the signature of the Unix one")]
fn exposed(_file: &File) -> io::Result<bool> {
    Ok(false)
}

/// The value of the hexadecimal digit `digit`.
fn digit(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use dedens_odoh::{ObliviousDoHConfigs, encrypt_query};
    use tempfile::NamedTempFile;

    use super::*;

    fn secret_file(text: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("a file");
        file.write_all(text.as_bytes()).expect("written");
        file
    }

    /// The same secret makes the same configurations; a generated key differs each time.
    #[test]
    fn a_file_fixes_the_key() {
        let file = secret_file(&format!("{}\n", "ab".repeat(SECRET_LEN)));
        let one = Target::new(Some(file.path())).expect("a target");
        let two = Target::new(Some(file.path())).expect("a target");
        assert_eq!(one.configs, two.configs);
        let generated = Target::new(None).expect("a target");
        assert_ne!(generated.configs, one.configs);
    }

    /// A reload compares the settings: the key's path, never its content, which is not read again.
    #[test]
    fn settings_differ_by_the_key_path() {
        let section = |path: Option<&str>| Section::new(path.map(Path::new), None);
        assert_eq!(section(Some("/a")), section(Some("/a")));
        assert_ne!(section(Some("/a")), section(Some("/b")));
        assert_ne!(section(Some("/a")), section(None));
        let proxy = |target: &str| {
            let settings = ProxySettings::new(&[target.to_owned()], None).expect("settings");
            Section::new(None, Some(settings))
        };
        assert_eq!(proxy("a.example"), proxy("A.example"));
        assert_ne!(proxy("a.example"), proxy("b.example"));
        assert_ne!(proxy("a.example"), section(None));
        // Nothing is read until the target is made.
        assert!(section(Some("/nonexistent/odoh.key")).target().is_err());
    }

    /// A key file longer than a key and its whitespace is refused, as is one others can read, which is warned about.
    #[cfg(unix)]
    #[test]
    fn a_long_key_file_is_refused_and_an_exposed_one_found() {
        use std::os::unix::fs::PermissionsExt as _;
        let file = secret_file(&format!("{}\n", "ab".repeat(KEY_FILE_MAX)));
        let error = Target::new(Some(file.path())).unwrap_err();
        assert!(format!("{error:#}").contains("longer"), "{error:#}");
        let file = secret_file(&format!("  {}\n\n\n", "ab".repeat(SECRET_LEN)));
        assert!(Target::new(Some(file.path())).is_ok(), "whitespace around");
        let open = || File::open(file.path()).expect("opens");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).expect("set");
        assert!(!exposed(&open()).expect("metadata"));
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o640)).expect("set");
        assert!(exposed(&open()).expect("metadata"));
    }

    #[test]
    fn a_key_file_that_is_not_hex_is_refused() {
        for text in [
            "",
            "ab",
            &"zz".repeat(SECRET_LEN),
            &"ab".repeat(SECRET_LEN + 1),
        ] {
            let file = secret_file(text);
            assert!(Target::new(Some(file.path())).is_err(), "{text:?}");
        }
        assert!(Target::new(Some(Path::new("/nonexistent/odoh.key"))).is_err());
    }

    /// RFC 9230 §4.3: a query opens to the DNS message and its reply seals to the client; a query to another key is
    /// 401, garbage 400.
    #[test]
    fn queries_open_and_replies_seal() {
        let target = Target::new(None).expect("a target");
        let configs = ObliviousDoHConfigs::parse(&target.configs).expect("configurations");
        let mut entropy = Entropy::new().expect("randomness");
        let (message, context) =
            encrypt_query(&configs.configs()[0], b"query", 0, &mut entropy).expect("a query");
        let (wire, sealing) = target.open(&message.encode()).expect("opens");
        assert_eq!(wire, b"query");
        let response = seal(sealing, b"reply").expect("seals");
        assert_eq!(response.status(), StatusCode::OK);
        let sealed = ObliviousDoHMessage::parse(response.body()).expect("a message");
        let plaintext = dedens_odoh::decrypt_response(&context, &sealed).expect("a reply");
        assert_eq!(plaintext.dns_message(), b"reply");
        let other = Target::new(None).expect("a target");
        assert_eq!(
            other.open(&message.encode()).err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(target.open(b"garbage").err(), Some(StatusCode::BAD_REQUEST));
    }
}
