//! Both sides together, for each encryption system: the padding of queries and responses, the size limits of the
//! UDP and TCP responses, truncation, and what each side refuses.
//!
//! The DNS messages are the draft's (Appendix 2), the response grown by copies of its answer where it has to be
//! large.

use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, CertificateError, ClientMagic, ClientNonce,
    ClientSession, EncryptQueryError, EncryptResponseError, EncryptionSystem, QueryContext,
    QueryPadding, ResolverKey, ResponseContext, ResponseError, SecretKey, SigningKey, Validity,
};
use dedens_proto::{Flags, Message};
use dedens_testkit::hex;

use crate::util::{Replay, array, seq};

const SYSTEMS: [EncryptionSystem; 2] = [
    EncryptionSystem::XSalsa20Poly1305,
    EncryptionSystem::XChaCha20Poly1305,
];

const DNS_QUERY: &str = "12340100000100000000000003777777076578616d706c6503636f6d0000010001";
const DNS_RESPONSE: &str = "12348180000100010000000003777777076578616d706c6503636f6d0000010001c00c0001000100000e1000045db8d822";

fn resolver_secret() -> SecretKey {
    SecretKey::from_bytes(array(&seq(0x20, 32)))
}

fn client_secret() -> SecretKey {
    SecretKey::from_bytes(array(&seq(0x40, 32)))
}

fn nonce() -> ClientNonce {
    ClientNonce::from_bytes(array(&seq(0xa0, 12)))
}

fn certificate(system: EncryptionSystem) -> Certificate {
    let provider = SigningKey::from_seed(&array(&seq(0, 32))).expect("a seed");
    Certificate::sign(
        &provider,
        CertificateBody {
            system,
            resolver_key: resolver_secret().public_key(),
            client_magic: ClientMagic::try_from(array(&seq(0xb1, 8))).expect("a magic"),
            serial: 1,
            validity: Validity::new(1, 2).expect("a validity"),
            extensions: Vec::new(),
        },
    )
}

fn client(system: EncryptionSystem) -> ClientSession {
    ClientSession::new(&certificate(system), &client_secret()).expect("a session")
}

fn resolver(system: EncryptionSystem) -> ResolverKey {
    ResolverKey::new(&certificate(system), resolver_secret()).expect("the certificate's key")
}

/// The query, sent, received: the packet, its context for the client and for the resolver.
fn send(
    system: EncryptionSystem,
    padding: QueryPadding,
) -> (Vec<u8>, QueryContext, ResponseContext) {
    let (packet, query_context) = client(system)
        .encrypt_query(&hex(DNS_QUERY), padding, nonce())
        .expect("the query");
    let (plaintext, response_context) =
        resolver(system).decrypt_query(&packet).expect("the packet");
    assert_eq!(plaintext, hex(DNS_QUERY));
    (packet, query_context, response_context)
}

fn rng() -> Replay {
    Replay::new(&[seq(0xc0, 12), seq(0xd0, 12)].concat())
}

fn truncated(message: &Message<'_>) -> bool {
    message.header.flags.contains(Flags::TC)
}

/// The DNS message in a packet, which the client reads.
fn read(context: &QueryContext, packet: &[u8]) -> Message<'static> {
    let wire = context.decrypt_response(packet).expect("readable");
    Message::decode(&wire)
        .expect("a message")
        .message
        .into_owned()
}

/// A DNS response to the query with `answers` copies of the draft's answer.
fn response_with(answers: usize) -> Vec<u8> {
    let wire = hex(DNS_RESPONSE);
    let mut message = Message::decode(&wire).expect("a response").message;
    let answer = message.answer[0].clone();
    message.answer = vec![answer; answers];
    message.to_vec().expect("an encoded response")
}

/// "Client Queries Over UDP", "Resolver Responses Over UDP": the query goes through and the response comes back,
/// with either system.
#[test]
fn round_trip() {
    for system in SYSTEMS {
        let (_, query_context, response_context) = send(system, QueryPadding::udp(33, 256));
        for carrier in [Carrier::Udp, Carrier::Tcp] {
            let packet = response_context
                .encrypt_response(&hex(DNS_RESPONSE), carrier, &mut rng())
                .expect("a response");
            assert_eq!(
                query_context.decrypt_response(&packet),
                Ok(hex(DNS_RESPONSE)),
                "{system:?} {carrier:?}"
            );
        }
    }
}

/// The two systems give different packets for the same inputs, and neither opens the other's.
#[test]
fn systems_do_not_mix() {
    let (xsalsa, _, _) = send(EncryptionSystem::XSalsa20Poly1305, QueryPadding::to(64));
    let (xchacha, _, _) = send(EncryptionSystem::XChaCha20Poly1305, QueryPadding::to(64));
    assert_ne!(xsalsa[68..], xchacha[68..]);
    assert!(
        resolver(EncryptionSystem::XChaCha20Poly1305)
            .decrypt_query(&xsalsa)
            .is_err()
    );
    assert!(
        resolver(EncryptionSystem::XSalsa20Poly1305)
            .decrypt_query(&xchacha)
            .is_err()
    );
}

/// "Padding For Client Queries Over UDP": the plaintext is a multiple of 64 bytes, the packet at least
/// `<min-query-len>` bytes, and a query too long for that is padded to the next multiple of 64.
#[test]
fn udp_query_padding() {
    for (min_packet_len, plaintext) in [(256, 192), (0, 64), (68 + 33, 64), (1500, 1472)] {
        let (packet, _, _) = send(
            EncryptionSystem::XChaCha20Poly1305,
            QueryPadding::udp(33, min_packet_len),
        );
        assert_eq!(packet.len() - 68, plaintext, "min {min_packet_len}");
    }
    // A query of 63 bytes has room for the marker only in the next block.
    assert_eq!(QueryPadding::udp(63, 0), QueryPadding::to(64));
    assert_eq!(QueryPadding::udp(64, 0), QueryPadding::to(128));
}

/// "Padding For Client Queries Over TCP": 1 to 256 bytes of padding, the plaintext a multiple of 64, whatever the
/// random byte and the length of the query.
#[test]
fn tcp_query_padding() {
    for query_len in [1, 33, 63, 64, 65, 127, 128, 500] {
        for byte in 0..=u8::MAX {
            let padding = QueryPadding::tcp(query_len, &mut Replay::new(&[byte]));
            let len = (query_len + 1..=query_len + 256)
                .find(|&len| padding == QueryPadding::to(len))
                .expect("1 to 256 bytes of padding");
            assert_eq!(len % 64, 0, "query {query_len} byte {byte}");
        }
    }
}

/// "Client Queries Over UDP": a query too large for the 4096 bytes of a packet is not sent.
#[test]
fn query_too_long() {
    let system = EncryptionSystem::XChaCha20Poly1305;
    let session = client(system);
    assert_eq!(
        session
            .encrypt_query(&hex(DNS_QUERY), QueryPadding::to(4096 - 68 + 1), nonce())
            .err(),
        Some(EncryptQueryError::TooLong)
    );
    let (packet, _) = session
        .encrypt_query(&hex(DNS_QUERY), QueryPadding::to(4096 - 68), nonce())
        .expect("the largest packet");
    assert_eq!(packet.len(), 4096);
}

/// A client asks no question that is not a DNS question: a message with none, or no message, is refused before
/// anything is sent.
#[test]
fn query_must_have_a_question() {
    let session = client(EncryptionSystem::XChaCha20Poly1305);
    let no_question = hex("123401000000000000000000");
    assert_eq!(
        session
            .encrypt_query(&no_question, QueryPadding::to(64), nonce())
            .err(),
        Some(EncryptQueryError::NoQuestion)
    );
    assert!(matches!(
        session
            .encrypt_query(&[1, 2, 3], QueryPadding::to(64), nonce())
            .err(),
        Some(EncryptQueryError::Dns(_))
    ));
}

/// "Padding For Resolver Responses": the plaintext is a multiple of 64 bytes, the padding 1 to 256 bytes, and
/// the same for the same query: a retransmission is padded as the first query was.
#[test]
fn response_padding_is_a_multiple_of_64_and_stable() {
    let tcp = |nonce| {
        let (_, _, context) = {
            let (packet, _) = client(EncryptionSystem::XChaCha20Poly1305)
                .encrypt_query(&hex(DNS_QUERY), QueryPadding::to(64), nonce)
                .expect("a query");
            resolver(EncryptionSystem::XChaCha20Poly1305)
                .decrypt_query(&packet)
                .map(|(plaintext, context)| (packet, plaintext, context))
                .expect("a packet")
        };
        context
            .encrypt_response(&hex(DNS_RESPONSE), Carrier::Tcp, &mut rng())
            .expect("a response")
    };
    let mut lengths = std::collections::BTreeSet::new();
    for first in 0..=255 {
        let packet = tcp(ClientNonce::from_bytes([first; 12]));
        let plaintext = packet.len() - 48;
        assert_eq!(plaintext % 64, 0);
        assert!((49 + 1..=49 + 256).contains(&plaintext));
        assert_eq!(
            tcp(ClientNonce::from_bytes([first; 12])).len(),
            packet.len(),
            "stable for nonce {first}"
        );
        lengths.insert(plaintext);
    }
    assert_eq!(lengths.into_iter().collect::<Vec<_>>(), [64, 128, 192, 256]);
}

/// "Resolver Responses Over UDP": the response packet is never larger than the query packet, the plaintext still a
/// multiple of 64 when it fits, and less when only that would break the limit.
#[test]
fn udp_response_is_no_larger_than_the_query() {
    for system in SYSTEMS {
        for query_padding in [64, 128, 192, 256, 1000] {
            let (packet, query_context, context) = send(system, QueryPadding::to(query_padding));
            for answers in [1, 5, 20] {
                let response = response_with(answers);
                let sent = context
                    .encrypt_response(&response, Carrier::Udp, &mut rng())
                    .expect("a response");
                assert!(
                    sent.len() <= packet.len(),
                    "{system:?} query {query_padding} answers {answers}"
                );
                let received = query_context.decrypt_response(&sent).expect("readable");
                let message = Message::decode(&received).expect("a message").message;
                assert_eq!(truncated(&message), message.answer.len() < answers);
                if !truncated(&message) {
                    assert_eq!(received, response);
                }
                if sent.len() < packet.len() {
                    assert_eq!(
                        (sent.len() - 48) % 64,
                        0,
                        "padded to a block unless the query packet is the limit"
                    );
                }
            }
        }
    }
}

/// "Resolver Responses Over UDP": a response that does not fit the query packet is not dropped: it is sent
/// truncated, TC set and the answers left out, and it still carries the ID and the question.
#[test]
fn oversized_udp_response_is_truncated() {
    let (packet, query_context, context) = send(
        EncryptionSystem::XChaCha20Poly1305,
        QueryPadding::udp(33, 256),
    );
    assert_eq!(packet.len(), 260);
    let response = response_with(100);
    let sent = context
        .encrypt_response(&response, Carrier::Udp, &mut rng())
        .expect("a response");
    assert!(sent.len() <= 260);
    let message = read(&query_context, &sent);
    assert!(truncated(&message));
    assert!(message.answer.len() < 100);
    assert_eq!(message.header.id, 0x1234);
    assert_eq!(message.questions.len(), 1);
}

/// "Resolver Responses Over TCP": no limit but the 4096 bytes of a packet, under which the response is sent whole
/// and above which it is truncated.
#[test]
fn tcp_response_is_under_4096() {
    let (_, query_context, context) =
        send(EncryptionSystem::XChaCha20Poly1305, QueryPadding::to(64));
    let fits = response_with(150);
    let sent = context
        .encrypt_response(&fits, Carrier::Tcp, &mut rng())
        .expect("a response");
    assert!(sent.len() < 4096);
    assert_eq!(query_context.decrypt_response(&sent), Ok(fits));

    let big = response_with(300);
    assert!(big.len() > 4096 - 48);
    let sent = context
        .encrypt_response(&big, Carrier::Tcp, &mut rng())
        .expect("a response");
    assert!(sent.len() < 4096);
    let message = read(&query_context, &sent);
    assert!(truncated(&message));
}

/// "Protocol Components": a response is under 4096 bytes even when the query packet is 4096 and the UDP budget
/// would allow as much.
#[test]
fn udp_response_to_the_largest_query_is_under_4096() {
    for system in SYSTEMS {
        let (packet, query_context, context) = send(system, QueryPadding::to(4096 - 68));
        assert_eq!(packet.len(), 4096);
        // 250 answers is 4033 bytes: padded to a block, it would be 4096 once encrypted.
        for answers in [250, 251, 300] {
            let sent = context
                .encrypt_response(&response_with(answers), Carrier::Udp, &mut rng())
                .expect("a response");
            assert!(sent.len() < 4096, "{system:?} answers {answers}");
            query_context.decrypt_response(&sent).expect("readable");
        }
    }
}

/// A query packet with no room for the response's header and question gets no response, an error to the caller
/// rather than a packet over the limit.
#[test]
fn no_room_for_a_response() {
    let system = EncryptionSystem::XChaCha20Poly1305;
    // The shortest query, for the root: a packet of 86 bytes, 38 for the response.
    let root_query = hex("123401000001000000000000000001 0001"
        .replace(' ', "")
        .as_str());
    let (packet, _) = client(system)
        .encrypt_query(&root_query, QueryPadding::to(1), nonce())
        .expect("the query");
    assert_eq!(packet.len(), 86);
    let (_, context) = resolver(system).decrypt_query(&packet).expect("a packet");
    // A response whose question is over 38 bytes cannot be cut to fit.
    let long_name = "1e".to_owned() + &"61".repeat(30);
    let response = hex(&format!("123481800001000000000000{long_name}000001 0001").replace(' ', ""));
    assert!(matches!(
        context.encrypt_response(&response, Carrier::Udp, &mut rng()),
        Err(EncryptResponseError::NoRoom(_))
    ));
    assert!(matches!(
        context.encrypt_response(&[0xff; 100], Carrier::Udp, &mut rng()),
        Err(EncryptResponseError::Dns(_))
    ));
}

/// "Protocol Components": the resolver half of the nonce is never all NUL; a draw of zeroes is drawn again.
#[test]
fn zero_resolver_nonce_is_redrawn() {
    let (_, query_context, context) =
        send(EncryptionSystem::XChaCha20Poly1305, QueryPadding::to(64));
    let mut zeroes_first = Replay::new(&[seq(0, 0), vec![0; 12], seq(0xd0, 12)].concat());
    let packet = context
        .encrypt_response(&hex(DNS_RESPONSE), Carrier::Tcp, &mut zeroes_first)
        .expect("a response");
    assert_eq!(packet[20..32], seq(0xd0, 12));
    assert_eq!(
        query_context.decrypt_response(&packet),
        Ok(hex(DNS_RESPONSE))
    );
}

/// The key of another certificate does not make a resolver key.
#[test]
fn resolver_key_must_be_the_certificates() {
    let certificate = certificate(EncryptionSystem::XChaCha20Poly1305);
    assert_eq!(
        ResolverKey::new(&certificate, client_secret()).err(),
        Some(CertificateError::KeyMismatch)
    );
}

/// "Client Queries Over UDP": a response is the answer to the query that was sent: its ID and its questions are
/// the query's.
#[test]
fn response_must_answer_the_query() {
    let system = EncryptionSystem::XChaCha20Poly1305;
    let (_, query_context, context) = send(system, QueryPadding::to(64));
    let wrong_id = {
        let mut response = hex(DNS_RESPONSE);
        response[1] ^= 1;
        response
    };
    let wrong_question = {
        let mut response = hex(DNS_RESPONSE);
        response[17] = b'X';
        response
    };
    assert_eq!(
        query_context.decrypt_response(
            &context
                .encrypt_response(&wrong_id, Carrier::Tcp, &mut rng())
                .expect("sent")
        ),
        Err(ResponseError::IdMismatch)
    );
    assert_eq!(
        query_context.decrypt_response(
            &context
                .encrypt_response(&wrong_question, Carrier::Tcp, &mut rng())
                .expect("sent")
        ),
        Err(ResponseError::QuestionMismatch)
    );
    assert_eq!(
        query_context
            .decrypt_response(
                &context
                    .encrypt_response(&[1; 5], Carrier::Tcp, &mut rng())
                    .expect("sent")
            )
            .map_err(|e| matches!(e, ResponseError::Dns(_))),
        Err(true)
    );
}

/// A client key that is the same for every query shares one key, which `decrypt_query_with` takes: the result is
/// that of `decrypt_query`, and the key of another client does not open the packet.
#[test]
fn shared_key_is_reused() {
    let system = EncryptionSystem::XChaCha20Poly1305;
    let (packet, _, _) = send(system, QueryPadding::to(64));
    let resolver = resolver(system);
    let client_key = resolver.client_key(&packet).expect("a key");
    let shared = resolver.shared_key(&client_key).expect("a shared key");
    assert_eq!(
        resolver
            .decrypt_query_with(&packet, &shared)
            .expect("a query")
            .0,
        hex(DNS_QUERY)
    );
    let other = resolver
        .shared_key(&SecretKey::from_bytes([5; 32]).public_key())
        .expect("a shared key");
    assert!(resolver.decrypt_query_with(&packet, &other).is_err());
}

/// "Certificate Retrieval" aside, a query too short for its fields, or too long, is dropped: every prefix of a
/// packet is `Truncated` or fails to authenticate, never a panic.
#[test]
fn truncated_packets() {
    let system = EncryptionSystem::XChaCha20Poly1305;
    let (packet, query_context, context) = send(system, QueryPadding::to(64));
    let resolver = resolver(system);
    for len in 0..packet.len() {
        assert!(
            resolver.decrypt_query(&packet[..len]).is_err(),
            "query prefix {len}"
        );
    }
    assert!(resolver.decrypt_query(&vec![0; 4097]).is_err());
    let response = context
        .encrypt_response(&hex(DNS_RESPONSE), Carrier::Tcp, &mut rng())
        .expect("sent");
    for len in 0..response.len() {
        assert!(
            query_context.decrypt_response(&response[..len]).is_err(),
            "response prefix {len}"
        );
    }
    assert_eq!(
        query_context.decrypt_response(&vec![0; 4096]),
        Err(ResponseError::TooLong)
    );
}
