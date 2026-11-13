//! What only the crate's inside can build: packets whose plaintext is authentic but wrongly padded, or whose
//! resolver nonce is zero, which no [`ClientSession`] or [`ResponseContext`] makes.

use chacha20::cipher::array::Array as ChaChaArray;
use chacha20::{R20, hchacha};
use dedens_testkit::hex;

use crate::secretbox::{self, TAG_LEN};
use crate::{
    Certificate, CertificateBody, ClientMagic, ClientNonce, ClientSession, EncryptionSystem,
    QueryError, ResolverKey, ResponseError, SecretKey, SigningKey, Validity, padding,
};

const DNS_QUERY: [u8; 33] = [
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w', b'w',
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
    0x01,
];

/// "Padding For Client Queries Over UDP": the marker is the last byte that is not NUL, and it is 0x80.
#[test]
fn unpadded_len_finds_the_marker() {
    assert_eq!(padding::unpadded_len(&[1, 2, 0x80]), Ok(2));
    assert_eq!(padding::unpadded_len(&[1, 2, 0x80, 0, 0, 0]), Ok(2));
    assert_eq!(padding::unpadded_len(&[0x80]), Ok(0));
    assert_eq!(padding::unpadded_len(&[1, 0x80, 0x80, 0]), Ok(2));
    for bad in [
        &[][..],
        &[0, 0],
        &[1, 2, 3],
        &[0x80, 1, 0],
        &[0x80, 0x81],
        &[0x7f, 0, 0],
    ] {
        assert!(padding::unpadded_len(bad).is_err(), "{bad:?}");
    }
}

/// The padding a message of `len` bytes takes to a block is 1 to 64 bytes, plus 64 for each extra block.
#[test]
fn to_block_is_one_to_256() {
    for len in 0..512 {
        for extra in 0..4 {
            let padded = len + padding::to_block(len, extra);
            assert_eq!(padded % 64, 0);
            assert!((1 + 64 * extra..=64 * (extra + 1)).contains(&(padded - len)));
        }
    }
}

fn certificate() -> (Certificate, SecretKey) {
    let provider = SigningKey::from_seed(&[1; 32]).expect("a seed");
    let secret = SecretKey::from_bytes([2; 32]);
    let certificate = Certificate::sign(
        &provider,
        CertificateBody {
            system: EncryptionSystem::XChaCha20Poly1305,
            resolver_key: secret.public_key(),
            client_magic: ClientMagic::try_from([9; 8]).expect("a magic"),
            serial: 1,
            validity: Validity::new(1, 2).expect("a validity"),
            extensions: Vec::new(),
        },
    );
    (certificate, secret)
}

/// "Client Queries Over UDP": a query whose plaintext authenticates but has no padding marker is dropped, as is
/// one whose padding is not NUL bytes.
#[test]
fn query_with_bad_padding_is_dropped() {
    let (certificate, secret) = certificate();
    let client = SecretKey::from_bytes([3; 32]);
    let session = ClientSession::new(&certificate, &client).expect("a session");
    let (valid, _) = session
        .encrypt_query(
            &DNS_QUERY,
            crate::QueryPadding::to(64),
            ClientNonce::from_bytes([4; 12]),
        )
        .expect("a query");
    let resolver = ResolverKey::new(&certificate, secret).expect("the key");
    assert!(resolver.decrypt_query(&valid).is_ok());

    let shared = client
        .shared_key(
            EncryptionSystem::XChaCha20Poly1305,
            &certificate.body().resolver_key,
        )
        .expect("a shared key");
    for plaintext in [
        [DNS_QUERY.to_vec(), vec![0; 31]].concat(),
        [DNS_QUERY.to_vec(), vec![0x81; 31]].concat(),
    ] {
        let mut packet = valid[..68 - TAG_LEN].to_vec();
        let mut ciphertext = plaintext;
        let tag = secretbox::seal(&shared, &secretbox::query_nonce(&[4; 12]), &mut ciphertext);
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&ciphertext);
        assert_eq!(
            resolver.decrypt_query(&packet).err(),
            Some(QueryError::Padding(crate::error::PaddingError))
        );
    }
}

/// "Resolver Responses Over UDP": a response that authenticates with no padding marker, or with a resolver nonce
/// of NUL bytes, is dropped by the client.
#[test]
fn response_with_bad_padding_or_zero_nonce_is_dropped() {
    let (certificate, secret) = certificate();
    let client = SecretKey::from_bytes([3; 32]);
    let session = ClientSession::new(&certificate, &client).expect("a session");
    let nonce = ClientNonce::from_bytes([4; 12]);
    let (_, context) = session
        .encrypt_query(&DNS_QUERY, crate::QueryPadding::to(64), nonce)
        .expect("a query");
    let shared = secret
        .shared_key(EncryptionSystem::XChaCha20Poly1305, &client.public_key())
        .expect("a shared key");

    let packet = |resolver_half: [u8; 12], plaintext: &[u8]| {
        let mut full_nonce = [4; 24];
        full_nonce[12..].copy_from_slice(&resolver_half);
        let mut ciphertext = plaintext.to_vec();
        let tag = secretbox::seal(&shared, &full_nonce, &mut ciphertext);
        [&crate::RESPONSE_MAGIC[..], &full_nonce, &tag, &ciphertext].concat()
    };
    let mut response = DNS_QUERY.to_vec();
    response[2] = 0x81;
    let mut padded = response.clone();
    padding::pad(&mut padded, 64);

    assert_eq!(
        context.decrypt_response(&packet([5; 12], &padded)),
        Ok(response.clone())
    );
    assert_eq!(
        context.decrypt_response(&packet([5; 12], &[response.clone(), vec![0; 3]].concat())),
        Err(ResponseError::Padding(crate::error::PaddingError))
    );
    assert_eq!(
        context.decrypt_response(&packet([0; 12], &padded)),
        Err(ResponseError::ZeroResolverNonce)
    );
}

/// "Test Vector For The HChaCha20 Block Function": the hash that makes the shared key of `0x0002` (with a NUL
/// input there) and the subkey of XChaCha20, as the draft pins it.
#[test]
fn hchacha20_block_vector() {
    let key: [u8; 32] = array_from(&hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ));
    let input: [u8; 16] = array_from(&hex("000102030405060708090a0b0c0d0e0f"));
    let out = hchacha::<R20>(&ChaChaArray::from(key), &ChaChaArray::from(input));
    assert_eq!(
        <[u8; 32]>::from(out).as_slice(),
        hex("51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6")
    );
}

/// `bytes` as an array of `N`.
fn array_from<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("N bytes")
}
