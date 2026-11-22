//! RFC 8945 §6 (the algorithms), §2 (keys) and §4.3.3 (names compare without case), D205.

use dedens_testkit::dns;
use dedens_tsig::{Algorithm, Key, KeyError, Keyring};

/// §6, D205: the SHA-2 family and SHA-1 are in, with the names and sizes RFC 4635 gives; MD5 is not.
#[test]
fn s6_the_algorithms() {
    let table = [
        (Algorithm::HmacSha1, "hmac-sha1", 20, 10),
        (Algorithm::HmacSha256, "hmac-sha256", 32, 16),
        (Algorithm::HmacSha384, "hmac-sha384", 48, 24),
        (Algorithm::HmacSha512, "hmac-sha512", 64, 32),
    ];
    for (algorithm, name, len, min) in table {
        assert_eq!(algorithm.to_string(), name);
        assert_eq!(algorithm.mac_len(), len);
        assert_eq!(algorithm.min_mac_len(), min);
        assert_eq!(name.parse(), Ok(algorithm));
        assert_eq!(format!("{name}.").parse(), Ok(algorithm));
        assert_eq!(name.to_uppercase().parse(), Ok(algorithm));
        assert_eq!(
            Algorithm::from_name(&dns(&format!("{name}."))),
            Some(algorithm)
        );
        assert_eq!(Algorithm::from_name(&algorithm.name()), Some(algorithm));
        assert_eq!(
            Algorithm::from_name(&dns(&format!("{}.", name.to_uppercase()))),
            Some(algorithm)
        );
    }
    assert!("hmac-md5".parse::<Algorithm>().is_err());
    assert_eq!(
        Algorithm::from_name(&dns("hmac-md5.sig-alg.reg.int.")),
        None
    );
    assert_eq!(Algorithm::from_name(&dns("hmac-sha256.example.")), None);
}

/// §2: a key needs a secret, and one given in base64 must be.
#[test]
fn s2_keys() {
    let name = dns("k.");
    assert_eq!(
        Key::new(name.clone(), Algorithm::HmacSha256, vec![]).unwrap_err(),
        KeyError::EmptySecret
    );
    assert_eq!(
        Key::from_base64(name.clone(), Algorithm::HmacSha256, "").unwrap_err(),
        KeyError::EmptySecret
    );
    assert_eq!(
        Key::from_base64(name.clone(), Algorithm::HmacSha256, "not base64!").unwrap_err(),
        KeyError::Base64
    );
    let key = Key::from_base64(name.clone(), Algorithm::HmacSha256, " AAECAw==\n").expect("valid");
    assert_eq!(key.name(), &name);
    assert_eq!(key.algorithm(), Algorithm::HmacSha256);
}

/// D205: the secret never reaches a log through `Debug`.
#[test]
fn d205_debug_hides_the_secret() {
    let key = Key::new(dns("k."), Algorithm::HmacSha256, b"correct horse".to_vec()).expect("valid");
    let shown = format!("{key:?} {:?}", Keyring::new([key.clone()]).expect("one"));
    assert!(!shown.contains("correct"), "{shown}");
    assert!(!shown.contains("99, 111"), "{shown}");
}

/// §4.3.3, §5.2.1: a keyring finds a key by name without case, and refuses two keys of one name.
#[test]
fn s4_3_3_the_keyring_compares_names_without_case() {
    let key = |name: &str| Key::new(dns(name), Algorithm::HmacSha256, vec![1]).expect("valid");
    let ring = Keyring::new([key("Alpha.example."), key("beta.")]).expect("distinct");
    assert_eq!(ring.len(), 2);
    assert!(!ring.is_empty());
    assert!(ring.get(&dns("alpha.EXAMPLE.")).is_some());
    assert!(ring.get(&dns("beta.")).is_some());
    assert!(ring.get(&dns("gamma.")).is_none());
    assert!(ring.get(&dns("alpha.")).is_none());
    assert_eq!(
        Keyring::new([key("a."), key("A.")]).unwrap_err(),
        KeyError::Duplicate(dns("A."))
    );
    assert!(Keyring::default().is_empty());
}
