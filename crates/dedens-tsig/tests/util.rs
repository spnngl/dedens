//! Shared helpers: the captures' key, messages, and a second implementation of RFC 8945 §4.3 written from the RFC
//! with `ring` alone, as the oracle for what the crate signs and the way to sign what the crate refuses (truncated
//! MACs, unsigned messages in a stream).

use dedens_proto::{Name, Tsig, TsigRecord, decode_base64, find_tsig};
use dedens_testkit::authoritative::{Packet, Recording, TSIG_KEY};
use dedens_testkit::dns;
use dedens_tsig::{Algorithm, Key, Keyring};
use ring::hmac;

/// The key the captures were signed with, as Knot holds it.
pub(crate) fn capture_key() -> Key {
    Key::from_base64(
        dns(&format!("{}.", TSIG_KEY.name)),
        TSIG_KEY
            .algorithm
            .parse()
            .expect("an algorithm of the crate"),
        TSIG_KEY.secret,
    )
    .expect("a valid secret")
}

/// The reference signer of the captures' key.
pub(crate) fn reference() -> Reference {
    let secret = decode_base64(TSIG_KEY.secret.as_bytes()).expect("base64");
    Reference::new(&capture_key(), &secret)
}

pub(crate) fn keyring() -> Keyring {
    Keyring::new([capture_key()]).expect("one key")
}

/// A query for `qname` and type A, with ID `id`, and no TSIG.
pub(crate) fn query(id: u16, qname: &str) -> Vec<u8> {
    let mut wire = id.to_be_bytes().to_vec();
    wire.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    wire.extend_from_slice(dns(qname).to_wire(&mut [0; 255]));
    wire.extend_from_slice(&[0, 1, 0, 1]);
    wire
}

/// The recorded (request, response) pairs of `id`, in order.
pub(crate) fn exchanges(id: &str) -> Vec<(Packet, Packet)> {
    Recording::read(id)
        .messages
        .chunks(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect()
}

pub(crate) fn tsig(wire: &[u8]) -> TsigRecord<'_> {
    find_tsig(wire).expect("well formed").expect("signed")
}

/// `wire` without its TSIG record: the bytes that were signed, with the count decremented.
pub(crate) fn strip(wire: &[u8]) -> Vec<u8> {
    let start = tsig(wire).start;
    let mut stripped = wire[..start].to_vec();
    let additional = u16::from_be_bytes([stripped[10], stripped[11]]) - 1;
    stripped[10..12].copy_from_slice(&additional.to_be_bytes());
    stripped
}

/// The name's wire form in lowercase (RFC 8945 §4.3.3).
pub(crate) fn lowercase(name: &Name<'_>) -> Vec<u8> {
    name.to_wire(&mut [0; 255]).to_ascii_lowercase()
}

/// The reference signer of RFC 8945 §4.3: the digest and the record, by hand.
pub(crate) struct Reference {
    name: Name<'static>,
    algorithm: Algorithm,
    key: hmac::Key,
}

impl Reference {
    pub(crate) fn new(key: &Key, secret: &[u8]) -> Self {
        let ring = match key.algorithm() {
            Algorithm::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::HmacSha256 => hmac::HMAC_SHA256,
            Algorithm::HmacSha384 => hmac::HMAC_SHA384,
            Algorithm::HmacSha512 => hmac::HMAC_SHA512,
            _ => unreachable!("every algorithm of the crate is above"),
        };
        Self {
            name: key.name().clone(),
            algorithm: key.algorithm(),
            key: hmac::Key::new(ring, secret),
        }
    }

    /// The MAC input for `message` (a message with no TSIG), after `before`: the request MAC or prior MAC with its
    /// size and the unsigned messages, in the form §4.3 and §5.3.1 give. `timers_only` is a stream's later message.
    #[expect(
        clippy::too_many_arguments,
        reason = "a test oracle: the fields of the RFC's digest, in its order"
    )]
    pub(crate) fn mac(
        &self,
        before: &[u8],
        message: &[u8],
        time: u64,
        fudge: u16,
        error: u16,
        other: &[u8],
        timers_only: bool,
    ) -> Vec<u8> {
        let mut input = before.to_vec();
        input.extend_from_slice(message);
        if !timers_only {
            input.extend_from_slice(&lowercase(&self.name));
            input.extend_from_slice(&255_u16.to_be_bytes());
            input.extend_from_slice(&0_u32.to_be_bytes());
            input.extend_from_slice(self.algorithm.wire());
        }
        input.extend_from_slice(&time.to_be_bytes()[2..]);
        input.extend_from_slice(&fudge.to_be_bytes());
        if !timers_only {
            input.extend_from_slice(&error.to_be_bytes());
            input.extend_from_slice(&u16::try_from(other.len()).expect("short").to_be_bytes());
            input.extend_from_slice(other);
        }
        hmac::sign(&self.key, &input).as_ref().to_vec()
    }

    /// `message` with a TSIG record of `mac`, which may be shorter than the full MAC, and the fields given.
    pub(crate) fn record(
        &self,
        message: &[u8],
        mac: &[u8],
        time: u64,
        fudge: u16,
        error: u16,
        other: &[u8],
    ) -> Vec<u8> {
        let mut rdata = self.algorithm.wire().to_vec();
        rdata.extend_from_slice(&time.to_be_bytes()[2..]);
        rdata.extend_from_slice(&fudge.to_be_bytes());
        rdata.extend_from_slice(&u16::try_from(mac.len()).expect("short").to_be_bytes());
        rdata.extend_from_slice(mac);
        rdata.extend_from_slice(&message[..2]);
        rdata.extend_from_slice(&error.to_be_bytes());
        rdata.extend_from_slice(&u16::try_from(other.len()).expect("short").to_be_bytes());
        rdata.extend_from_slice(other);
        let mut wire = message.to_vec();
        let additional = u16::from_be_bytes([wire[10], wire[11]]) + 1;
        wire[10..12].copy_from_slice(&additional.to_be_bytes());
        wire.extend_from_slice(self.name.to_wire(&mut [0; 255]));
        wire.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
        wire.extend_from_slice(&u16::try_from(rdata.len()).expect("short").to_be_bytes());
        wire.extend_from_slice(&rdata);
        wire
    }

    /// A request or the first message of a response signed as §5.1 and §5.3 say, its MAC cut to `mac_len`.
    /// `request_mac` is the request's, empty for a request. Returns the message and its MAC.
    pub(crate) fn sign(
        &self,
        request_mac: &[u8],
        message: &[u8],
        time: u64,
        fudge: u16,
        mac_len: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let before = sized(request_mac);
        let mac = self.mac(&before, message, time, fudge, 0, &[], false);
        (
            self.record(message, &mac[..mac_len], time, fudge, 0, &[]),
            mac[..mac_len].to_vec(),
        )
    }

    /// A later message of a stream (§5.3.1): `prior` is the last MAC, `unsigned` the messages since it, which
    /// the MAC covers. Returns the message and its MAC.
    pub(crate) fn sign_next(
        &self,
        prior: &[u8],
        unsigned: &[Vec<u8>],
        message: &[u8],
        time: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut before = sized(prior);
        before.extend(unsigned.concat());
        let mac = self.mac(&before, message, time, 300, 0, &[], true);
        (self.record(message, &mac, time, 300, 0, &[]), mac)
    }
}

/// A MAC with its size, as a digest takes it.
pub(crate) fn sized(mac: &[u8]) -> Vec<u8> {
    if mac.is_empty() {
        return Vec::new();
    }
    let mut out = u16::try_from(mac.len())
        .expect("short")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(mac);
    out
}

/// `message` with the TSIG record `owner` and `tsig` appended, however wrong they are.
pub(crate) fn with_tsig(message: &[u8], owner: &Name<'_>, tsig: &Tsig<'_>) -> Vec<u8> {
    let rdata = tsig.to_wire();
    let mut wire = message.to_vec();
    let additional = u16::from_be_bytes([wire[10], wire[11]]) + 1;
    wire[10..12].copy_from_slice(&additional.to_be_bytes());
    wire.extend_from_slice(owner.to_wire(&mut [0; 255]));
    wire.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
    wire.extend_from_slice(&u16::try_from(rdata.len()).expect("short").to_be_bytes());
    wire.extend_from_slice(&rdata);
    wire
}
