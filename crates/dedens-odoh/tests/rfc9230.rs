//! RFC 9230: configs (§5), message formats (§6.1), the query and response encryption (§6.2, §7, §8).
//!
//! Real data: the config Cloudflare serves, and the vectors of `cloudflare/odoh-go`; both are described in
//! `testdata/odoh/README.md`. Nothing else in RFC 9230 is a byte-level example.

mod common;

use std::fs;

use common::{Replay, hex};
use dedens_odoh::{
    ConfigContents, Configs, ExchangeError, Message, MessagePlaintext, MessageType, QUERY_BLOCK,
    RESPONSE_BLOCK, TargetKey, WireError, decrypt_query, decrypt_response, encrypt_query,
    encrypt_response, query_padding, response_padding, suite,
};
use hpke::{Deserializable as _, OpModeS, Serializable as _};
use ring::{aead, hkdf};
use serde::Deserialize;

fn testdata(name: &str) -> Vec<u8> {
    fs::read(dedens_testkit::path("odoh").join(name)).expect("test data file")
}

#[derive(Deserialize)]
struct Vector {
    odohconfigs: String,
    public_key_seed: String,
    key_id: String,
    transactions: Vec<Transaction>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Transaction {
    query: String,
    query_padding_length: usize,
    response: String,
    response_padding_length: usize,
    oblivious_query: String,
    oblivious_response: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_slice(&testdata("odoh-go-test-vectors.json")).expect("the odoh-go vectors")
}

/// A target key, and the same bytes every run.
fn target() -> TargetKey {
    TargetKey::derive(&[7; 32])
}

/// The 32 bytes of a hex seed.
fn seed(text: &str) -> [u8; 32] {
    hex(text).try_into().expect("a seed of 32 bytes")
}

/// A full exchange of `query` and `response` under `key`, with fixed "random" bytes.
fn exchange(key: &TargetKey, query: &[u8], response: &[u8]) -> (Message, Message) {
    let (query_message, client) = encrypt_query(
        key.config(),
        query,
        query_padding(query.len()),
        &mut Replay::new(&[1; 32]),
    )
    .expect("encrypts");
    let (plaintext, target) = decrypt_query(key, &query_message).expect("decrypts");
    assert_eq!(plaintext.dns_message(), query);
    let response_message = encrypt_response(
        target,
        response,
        response_padding(response.len()),
        &mut Replay::new(&[2; 16]),
    )
    .expect("encrypts");
    let plaintext = decrypt_response(&client, &response_message).expect("decrypts");
    assert_eq!(plaintext.dns_message(), response);
    (query_message, response_message)
}

// §5 ------------------------------------------------------------------------------------------------------

#[test]
fn cloudflare_config_parses_and_round_trips() {
    let wire = testdata("odohconfigs-cloudflare.bin");
    let configs = Configs::parse(&wire).expect("parses");
    let [config] = configs.configs() else {
        panic!("one config, not {}", configs.configs().len());
    };
    assert_eq!(
        config.public_key().as_slice(),
        hex("ee740b2780bda354a1c474496ecd1b41dfdddcd4c9b09fc76c84c464ff87a966")
    );
    assert_eq!(configs.encode(), Ok(wire));
}

#[test]
fn cloudflare_config_encrypts_a_query() {
    let wire = testdata("odohconfigs-cloudflare.bin");
    let configs = Configs::parse(&wire).expect("parses");
    let (message, _) = encrypt_query(&configs.configs()[0], b"dns", 0, &mut Replay::new(&[3; 32]))
        .expect("encrypts");
    assert_eq!(message.key_id(), configs.configs()[0].key_id());
}

#[test]
fn truncated_and_extended_lists_are_refused() {
    let wire = testdata("odohconfigs-cloudflare.bin");
    for len in 0..wire.len() {
        assert!(Configs::parse(&wire[..len]).is_err(), "{len} bytes");
    }
    let mut longer = wire;
    longer.push(0);
    assert_eq!(Configs::parse(&longer), Err(WireError::TrailingBytes));
}

#[test]
fn an_empty_list_is_refused() {
    assert_eq!(
        Configs::parse(&[0, 0]),
        Err(WireError::EmptyField("ObliviousDoHConfigs"))
    );
}

/// One `ObliviousDoHConfig`: `version`, then `length` and `contents` with the ids and a key of `key_len`.
fn config(version: u16, kem: u16, kdf: u16, aead: u16, key_len: usize) -> Vec<u8> {
    let mut contents = Vec::new();
    for id in [kem, kdf, aead] {
        contents.extend_from_slice(&id.to_be_bytes());
    }
    contents.extend_from_slice(&u16::try_from(key_len).expect("small").to_be_bytes());
    contents.extend(std::iter::repeat_n(9, key_len));
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(&u16::try_from(contents.len()).expect("small").to_be_bytes());
    out.extend(contents);
    out
}

fn list(configs: &[Vec<u8>]) -> Vec<u8> {
    let body = configs.concat();
    let mut out = u16::try_from(body.len())
        .expect("small")
        .to_be_bytes()
        .to_vec();
    out.extend(body);
    out
}

#[test]
fn configs_this_crate_cannot_use_are_skipped() {
    let ours = config(1, 0x20, 1, 1, 32);
    let parsed = Configs::parse(&list(&[
        config(2, 0x20, 1, 1, 32), // another version
        config(1, 0x10, 1, 1, 65), // P-256 KEM
        config(1, 0x20, 2, 1, 32), // HKDF-SHA384
        config(1, 0x20, 1, 2, 32), // AES-256-GCM
        ours.clone(),
    ]))
    .expect("parses");
    assert_eq!(parsed.configs().len(), 1);
    assert_eq!(parsed.encode(), Ok(list(&[ours])));
}

#[test]
fn a_list_without_a_usable_config_is_refused() {
    assert_eq!(
        Configs::parse(&list(&[config(2, 0x20, 1, 1, 32)])),
        Err(WireError::NoUsableConfig)
    );
}

/// A config of ours with a key of the wrong length, an empty key and bytes after its fields: malformed
/// each, and skipped as long as the list is well framed.
fn malformed_configs() -> Vec<Vec<u8>> {
    let mut trailing = config(1, 0x20, 1, 1, 32);
    trailing.push(0);
    trailing[3] += 1; // `length` counts the extra byte
    vec![
        config(1, 0x20, 1, 1, 31),
        config(1, 0x20, 1, 1, 0),
        config(1, 0x10, 1, 1, 0),
        trailing,
        vec![0, 1, 0, 3, 0, 0x20, 0], // the key's length is cut off
    ]
}

#[test]
fn malformed_configs_are_skipped_not_fatal() {
    let ours = config(1, 0x20, 1, 1, 32);
    for bad in malformed_configs() {
        let parsed = Configs::parse(&list(&[bad.clone(), ours.clone()])).expect("parses");
        assert_eq!(parsed.encode(), Ok(list(std::slice::from_ref(&ours))));
        assert_eq!(
            Configs::parse(&list(&[bad])),
            Err(WireError::NoUsableConfig)
        );
    }
}

#[test]
fn a_config_running_past_the_list_is_refused() {
    let mut cut = list(&[config(1, 0x20, 1, 1, 32)]);
    cut.truncate(cut.len() - 1);
    cut[1] -= 1; // the list's length follows the cut: only the config's own `length` is wrong
    assert_eq!(Configs::parse(&cut), Err(WireError::Truncated));
}

// §6.1 ----------------------------------------------------------------------------------------------------

#[test]
fn the_key_id_follows_the_config() {
    for vector in vectors() {
        let configs = Configs::parse(&hex(&vector.odohconfigs)).expect("parses");
        assert_eq!(
            configs.configs()[0].key_id().as_slice(),
            hex(&vector.key_id)
        );
        let key = TargetKey::derive(&seed(&vector.public_key_seed));
        assert_eq!(key.config(), &configs.configs()[0]);
    }
}

#[test]
fn messages_with_a_bad_frame_are_refused() {
    let good = Message::new(MessageType::Query, vec![1; 32], vec![2; 5]).expect("fits");
    let wire = good.encode();
    assert_eq!(Message::parse(&wire), Ok(good));
    for len in 0..wire.len() {
        assert!(Message::parse(&wire[..len]).is_err(), "{len} bytes");
    }
    let mut longer = wire.clone();
    longer.push(0);
    assert_eq!(Message::parse(&longer), Err(WireError::TrailingBytes));
    let mut unknown = wire;
    unknown[0] = 3;
    assert_eq!(
        Message::parse(&unknown),
        Err(WireError::UnknownMessageType(3))
    );
    assert_eq!(
        Message::parse(&[1, 0, 0, 0, 0]),
        Err(WireError::EmptyField("encrypted_message"))
    );
}

#[test]
fn plaintext_with_non_zero_padding_is_refused() {
    assert_eq!(
        MessagePlaintext::parse(&[0, 1, 7, 0, 2, 0, 1]),
        Err(WireError::NonZeroPadding)
    );
    assert_eq!(
        MessagePlaintext::parse(&[0, 0, 0, 0]),
        Err(WireError::EmptyField("dns_message"))
    );
    assert_eq!(
        MessagePlaintext::parse(&[0, 1, 7, 0, 0, 0]),
        Err(WireError::TrailingBytes)
    );
}

// §6.2, §8: vectors of odoh-go ------------------------------------------------------------------------------

#[test]
fn the_target_decrypts_and_answers_as_odoh_go_does() {
    for vector in vectors() {
        let key = TargetKey::derive(&seed(&vector.public_key_seed));
        for transaction in &vector.transactions {
            let query = Message::parse(&hex(&transaction.oblivious_query)).expect("parses");
            let (plaintext, context) = decrypt_query(&key, &query).expect("decrypts");
            assert_eq!(plaintext.dns_message(), hex(&transaction.query));
            assert_eq!(plaintext.padding(), transaction.query_padding_length);

            // The response nonce is the key ID of the vector's response; AES-GCM is deterministic.
            let expected = hex(&transaction.oblivious_response);
            let nonce = Message::parse(&expected).expect("parses");
            let response = encrypt_response(
                context,
                &hex(&transaction.response),
                transaction.response_padding_length,
                &mut Replay::new(nonce.key_id()),
            )
            .expect("encrypts");
            assert_eq!(response.encode(), expected);
        }
    }
}

// §6.2, §7, §8: round trips ---------------------------------------------------------------------------------

#[test]
fn a_query_and_its_response_round_trip() {
    let key = target();
    exchange(&key, b"\x12\x34 a query", b"\x12\x34 a response");
}

#[test]
fn padding_hides_the_length_within_a_block() {
    let key = target();
    let (short, short_response) = exchange(&key, &[1; 20], &[2; 20]);
    let (long, long_response) = exchange(&key, &[1; 100], &[2; 400]);
    assert_eq!(short.encode().len(), long.encode().len());
    assert_eq!(short_response.encode().len(), long_response.encode().len());
    // 2 + 2 lengths of the plaintext, 32 of the encapsulated key, 16 of the tag, 5 of the frame.
    assert_eq!(short.encode().len(), 5 + 32 + QUERY_BLOCK + 4 + 16 + 32);
    assert_eq!(
        short_response.encode().len(),
        5 + 16 + RESPONSE_BLOCK + 4 + 16
    );
}

#[test]
fn a_flipped_bit_in_a_query_is_refused() {
    let key = target();
    let (query, _) = exchange(&key, b"query", b"response");
    let wire = query.encode();
    for index in 0..wire.len() {
        let mut flipped = wire.clone();
        flipped[index] ^= 1;
        let outcome = Message::parse(&flipped)
            .map_err(ExchangeError::from)
            .and_then(|message| decrypt_query(&key, &message).map(|_| ()));
        assert!(outcome.is_err(), "byte {index}");
    }
}

#[test]
fn a_flipped_bit_in_a_response_is_refused() {
    let key = target();
    let (_, response) = exchange(&key, b"query", b"response");
    let wire = response.encode();
    for index in 0..wire.len() {
        let mut flipped = wire.clone();
        flipped[index] ^= 1;
        // The same query as in `exchange`, so the same secrets.
        let (_, client) = encrypt_query(
            key.config(),
            b"query",
            query_padding(5),
            &mut Replay::new(&[1; 32]),
        )
        .expect("encrypts");
        let outcome = Message::parse(&flipped)
            .map_err(ExchangeError::from)
            .and_then(|message| decrypt_response(&client, &message).map(|_| ()));
        assert!(outcome.is_err(), "byte {index}");
    }
}

#[test]
fn a_response_to_another_query_is_refused() {
    let key = target();
    let (_, response) = exchange(&key, b"query", b"response");
    let (_, other) =
        encrypt_query(key.config(), b"other", 0, &mut Replay::new(&[5; 32])).expect("encrypts");
    assert_eq!(
        decrypt_response(&other, &response),
        Err(ExchangeError::Decrypt)
    );
}

#[test]
fn a_query_for_another_key_is_unknown() {
    let key = target();
    let (query, _) = exchange(&key, b"query", b"response");
    assert_eq!(
        decrypt_query(&TargetKey::derive(&[8; 32]), &query).map(|_| ()),
        Err(ExchangeError::UnknownKey)
    );
}

#[test]
fn the_message_type_must_match() {
    let key = target();
    let (query, response) = exchange(&key, b"query", b"response");
    assert_eq!(
        decrypt_query(&key, &response).map(|_| ()),
        Err(ExchangeError::WrongType {
            expected: MessageType::Query,
            found: MessageType::Response
        })
    );
    let (_, client) =
        encrypt_query(key.config(), b"query", 0, &mut Replay::new(&[1; 32])).expect("encrypts");
    assert_eq!(
        decrypt_response(&client, &query),
        Err(ExchangeError::WrongType {
            expected: MessageType::Response,
            found: MessageType::Query
        })
    );
}

#[test]
fn a_response_nonce_of_the_wrong_length_is_refused() {
    let key = target();
    let (_, client) =
        encrypt_query(key.config(), b"query", 0, &mut Replay::new(&[1; 32])).expect("encrypts");
    let message = Message::new(MessageType::Response, vec![0; 15], vec![0; 20]).expect("fits");
    assert_eq!(
        decrypt_response(&client, &message),
        Err(ExchangeError::ResponseNonceLength(15))
    );
}

#[test]
fn a_truncated_encapsulated_key_is_a_wire_error() {
    let key = target();
    let message = Message::new(
        MessageType::Query,
        key.config().key_id().to_vec(),
        vec![0; 31],
    )
    .expect("fits");
    assert_eq!(
        decrypt_query(&key, &message).map(|_| ()),
        Err(ExchangeError::Wire(WireError::Truncated))
    );
}

/// What an independent client sends: HPKE through the crate's API, the framing by hand.
fn raw_query(config: &ConfigContents, plaintext: &[u8]) -> Message {
    let public_key =
        <suite::Kem as hpke::Kem>::PublicKey::from_bytes(config.public_key()).expect("32 bytes");
    let (enc, mut context) = hpke::setup_sender_with_rng::<suite::Aead, suite::Kdf, suite::Kem>(
        &OpModeS::Base,
        &public_key,
        b"odoh query",
        &mut Replay::new(&[4; 32]),
    )
    .expect("sets up");
    let mut aad = vec![1, 0, 32];
    aad.extend_from_slice(config.key_id());
    let sealed = context.seal(plaintext, &aad).expect("seals");
    let encrypted = [enc.to_bytes().as_slice(), &sealed].concat();
    Message::new(MessageType::Query, config.key_id().to_vec(), encrypted).expect("fits")
}

#[test]
fn the_target_reads_a_query_built_without_this_crate() {
    let key = target();
    // dns_message "ab", padding of two zeros.
    let (plaintext, _) = decrypt_query(
        &key,
        &raw_query(key.config(), &[0, 2, b'a', b'b', 0, 2, 0, 0]),
    )
    .expect("decrypts");
    assert_eq!(
        (plaintext.dns_message(), plaintext.padding()),
        (&b"ab"[..], 2)
    );
}

#[test]
fn a_query_with_non_zero_padding_is_refused() {
    let key = target();
    assert_eq!(
        decrypt_query(
            &key,
            &raw_query(key.config(), &[0, 2, b'a', b'b', 0, 2, 0, 1])
        )
        .map(|_| ()),
        Err(ExchangeError::Wire(WireError::NonZeroPadding))
    );
}

#[test]
fn a_query_with_trailing_plaintext_is_refused() {
    let key = target();
    assert_eq!(
        decrypt_query(&key, &raw_query(key.config(), &[0, 2, b'a', b'b', 0, 0, 0])).map(|_| ()),
        Err(ExchangeError::Wire(WireError::TrailingBytes))
    );
}

#[test]
fn empty_and_over_long_dns_messages_are_refused() {
    let key = target();
    assert_eq!(
        encrypt_query(key.config(), b"", 0, &mut Replay::new(&[1; 32])).map(|_| ()),
        Err(ExchangeError::Wire(WireError::EmptyField("dns_message")))
    );
    assert_eq!(
        encrypt_query(key.config(), &vec![0; 65536], 0, &mut Replay::new(&[1; 32])).map(|_| ()),
        Err(ExchangeError::Wire(WireError::FieldTooLong("dns_message")))
    );
}

// Key exchange and AEAD failures --------------------------------------------------------------------------

#[test]
fn a_public_key_of_small_order_is_an_encapsulation_error() {
    let weak = ConfigContents::new([0; 32]);
    assert_eq!(
        encrypt_query(&weak, b"query", 0, &mut Replay::new(&[1; 32])).map(|_| ()),
        Err(ExchangeError::Encapsulation)
    );
}

#[test]
fn an_encapsulated_key_of_small_order_is_a_decapsulation_error() {
    let key = target();
    let message = Message::new(
        MessageType::Query,
        key.config().key_id().to_vec(),
        vec![0; 32 + 16 + 4],
    )
    .expect("fits");
    assert_eq!(
        decrypt_query(&key, &message).map(|_| ()),
        Err(ExchangeError::Decapsulation)
    );
}

#[test]
fn a_ciphertext_shorter_than_the_tag_is_refused() {
    let key = target();
    let (query, client) =
        encrypt_query(key.config(), b"query", 0, &mut Replay::new(&[1; 32])).expect("encrypts");
    // The encapsulated key and 15 bytes: one short of the tag.
    let short = Message::new(
        MessageType::Query,
        query.key_id().to_vec(),
        query.encrypted_message()[..32 + 15].to_vec(),
    )
    .expect("fits");
    assert_eq!(
        decrypt_query(&key, &short).map(|_| ()),
        Err(ExchangeError::Decrypt)
    );
    let response = Message::new(MessageType::Response, vec![0; 16], vec![0; 15]).expect("fits");
    assert_eq!(
        decrypt_response(&client, &response),
        Err(ExchangeError::Decrypt)
    );
}

/// A response sealed as a target would, but for the plaintext, which `plaintext` sets: the client of
/// `encrypt_query` with `Replay::new(&[4; 32])` and `raw_query`'s HPKE setup share their secrets.
fn raw_response(config: &ConfigContents, query_plaintext: &[u8], plaintext: &[u8]) -> Message {
    let public_key =
        <suite::Kem as hpke::Kem>::PublicKey::from_bytes(config.public_key()).expect("32 bytes");
    let (_, context) = hpke::setup_sender_with_rng::<suite::Aead, suite::Kdf, suite::Kem>(
        &OpModeS::Base,
        &public_key,
        b"odoh query",
        &mut Replay::new(&[4; 32]),
    )
    .expect("sets up");
    let mut exporter = [0; 16];
    context
        .export(b"odoh response", &mut exporter)
        .expect("exports");

    let nonce = [6; 16];
    let salt = [query_plaintext, &[0, 16], &nonce].concat();
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&exporter);
    let expand = |info: &[u8], len: usize| {
        let mut out = vec![0; len];
        prk.expand(&[info], Len(len))
            .and_then(|okm| okm.fill(&mut out))
            .expect("expands");
        out
    };
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &expand(b"odoh key", 16)).expect("a key"),
    );
    let aead_nonce =
        aead::Nonce::try_assume_unique_for_key(&expand(b"odoh nonce", 12)).expect("12");
    let mut sealed = plaintext.to_vec();
    key.seal_in_place_append_tag(
        aead_nonce,
        aead::Aad::from([&[2, 0, 16][..], &nonce].concat()),
        &mut sealed,
    )
    .expect("seals");
    Message::new(MessageType::Response, nonce.to_vec(), sealed).expect("fits")
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

#[test]
fn a_response_sealed_by_hand_opens_and_its_padding_is_checked() {
    let key = target();
    let query_plaintext = [0, 2, b'a', b'b', 0, 2, 0, 0];
    let (_, client) =
        encrypt_query(key.config(), b"ab", 2, &mut Replay::new(&[4; 32])).expect("encrypts");
    let good = raw_response(key.config(), &query_plaintext, &[0, 1, b'r', 0, 2, 0, 0]);
    let plaintext = decrypt_response(&client, &good).expect("decrypts");
    assert_eq!(
        (plaintext.dns_message(), plaintext.padding()),
        (&b"r"[..], 2)
    );
    let dirty = raw_response(key.config(), &query_plaintext, &[0, 1, b'r', 0, 2, 0, 1]);
    assert_eq!(
        decrypt_response(&client, &dirty),
        Err(ExchangeError::Wire(WireError::NonZeroPadding))
    );
}

#[test]
fn a_forged_response_does_not_cost_the_context() {
    let key = target();
    let (_, client) =
        encrypt_query(key.config(), b"ab", 2, &mut Replay::new(&[4; 32])).expect("encrypts");
    let forged = Message::new(MessageType::Response, vec![0; 16], vec![0; 40]).expect("fits");
    assert_eq!(
        decrypt_response(&client, &forged),
        Err(ExchangeError::Decrypt)
    );
    let good = raw_response(
        key.config(),
        &[0, 2, b'a', b'b', 0, 2, 0, 0],
        &[0, 1, b'r', 0, 0],
    );
    assert!(decrypt_response(&client, &good).is_ok());
}

// Bounds --------------------------------------------------------------------------------------------------

#[test]
fn a_plaintext_that_overflows_the_encrypted_message_is_refused() {
    let key = target();
    // 65535 bytes of DNS message fit their own field, but not the ciphertext with the key and the tag.
    let long = vec![1; 65535];
    assert_eq!(
        encrypt_query(key.config(), &long, 0, &mut Replay::new(&[1; 32])).map(|_| ()),
        Err(ExchangeError::Wire(WireError::FieldTooLong(
            "encrypted_message"
        )))
    );
    let (query, _) =
        encrypt_query(key.config(), b"q", 0, &mut Replay::new(&[1; 32])).expect("encrypts");
    let (_, target) = decrypt_query(&key, &query).expect("decrypts");
    assert_eq!(
        encrypt_response(target, &long, 0, &mut Replay::new(&[2; 16])).map(|_| ()),
        Err(ExchangeError::Wire(WireError::FieldTooLong(
            "encrypted_message"
        )))
    );
}

#[test]
fn padding_over_65535_is_refused() {
    let key = target();
    assert_eq!(
        encrypt_query(key.config(), b"q", 65536, &mut Replay::new(&[1; 32])).map(|_| ()),
        Err(ExchangeError::Wire(WireError::FieldTooLong("padding")))
    );
}
