//! `dedensd` as an Oblivious `DoH` target (RFC 9230 §8, D79): the key, the configurations served for it, and the
//! opening of queries and sealing of replies.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use dedens_net::odoh::{self, Entropy};
use dedens_odoh::{
    ExchangeError, ObliviousDoHConfigs, ObliviousDoHMessage, ResponseContext, TargetKey,
    decrypt_query, encrypt_response, response_padding,
};
use http::{Response, StatusCode};
use zeroize::Zeroizing;

/// How long clients may keep the configurations, in seconds (D79).
const CONFIGS_MAX_AGE: u32 = 3600;

/// The bytes of the secret a key derives from (D78).
const SECRET_LEN: usize = 32;

/// The key of a target and the configurations that go with it.
#[derive(Debug)]
pub(crate) struct Target {
    /// The file the secret was read from; `None` for one generated at start.
    source: Option<PathBuf>,
    key: TargetKey,
    /// The encoded configurations (RFC 9230 §5), served at the well-known path.
    configs: Vec<u8>,
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
            source: file.map(Path::to_path_buf),
            key,
            configs,
        })
    }

    /// Where the secret came from: a change takes a restart.
    pub(crate) fn source(&self) -> Option<&Path> {
        self.source.as_deref()
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
    encrypt_response(context, wire, response_padding(wire.len()), &mut entropy)
        .map(|message| odoh::target_response(&message))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// The secret in `file`: [`SECRET_LEN`] bytes as hexadecimal digits, surrounding whitespace aside.
fn read_secret(file: &Path) -> anyhow::Result<Zeroizing<[u8; SECRET_LEN]>> {
    let text = Zeroizing::new(
        std::fs::read_to_string(file)
            .with_context(|| format!("`odoh`: cannot read the key {}", file.display()))?,
    );
    let (pairs, rest) = text.trim().as_bytes().as_chunks::<2>();
    let mut secret = Zeroizing::new([0; SECRET_LEN]);
    ensure!(
        rest.is_empty() && pairs.len() == SECRET_LEN,
        "`odoh`: the key {} is not {} hexadecimal digits",
        file.display(),
        2 * SECRET_LEN
    );
    for (byte, &[high, low]) in secret.iter_mut().zip(pairs) {
        let (Some(high), Some(low)) = (digit(high), digit(low)) else {
            bail!(
                "`odoh`: the key {} has a character that is no hexadecimal digit",
                file.display()
            );
        };
        *byte = high << 4 | low;
    }
    Ok(secret)
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
        assert_eq!(one.source(), Some(file.path()));
        let generated = Target::new(None).expect("a target");
        assert_ne!(generated.configs, one.configs);
        assert_eq!(generated.source(), None);
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
