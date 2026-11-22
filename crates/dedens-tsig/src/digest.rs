//! The MAC computation (RFC 8945 §4.3) and appending the TSIG record to a message (§5.1, §5.3).

use std::fmt;

use dedens_proto::{
    Class, HEADER_LEN, MAX_MESSAGE_LEN, MAX_NAME_LEN, Name, RecordType, Tsig, TsigDataError,
    TsigError, TsigRecord,
};
use ring::hmac;
use subtle::ConstantTimeEq;

use crate::algorithm::MIN_MAC_LEN;
use crate::key::{Key, canonical};

/// Why a message cannot be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The message is shorter than a header (RFC 1035 §4.1.1).
    #[error("message is shorter than a DNS header")]
    Header,
    /// The additional section has 65535 records already.
    #[error("additional record count is full")]
    Count,
    /// The message with the TSIG record is over 65535 bytes. Over UDP the answer is the question and the TSIG with
    /// TC set (RFC 8945 §5.3), which the caller builds.
    #[error("message with its TSIG is longer than 65535 bytes")]
    TooLong,
    /// The TSIG data does not fit its fields.
    #[error(transparent)]
    Data(#[from] TsigDataError),
}

/// The bytes a MAC is computed over, fed in the order of RFC 8945 §4.3. A clone is the same digest so far: the
/// client checks a message on one and keeps it only when the message is accepted.
#[derive(Clone)]
pub(crate) struct Digest(hmac::Context);

impl Digest {
    pub(crate) fn new(key: &Key) -> Self {
        Self(hmac::Context::with_key(&key.hmac()))
    }

    /// A MAC as the digest takes it, with its size (RFC 8945 §4.3.1, §5.3.1).
    pub(crate) fn mac(&mut self, mac: &[u8]) {
        // A MAC has at most 64 bytes.
        self.0
            .update(&u16::try_from(mac.len()).unwrap_or(u16::MAX).to_be_bytes());
        self.0.update(mac);
    }

    /// Bytes as they are: a message to sign, or one that came with no TSIG (RFC 8945 §5.3.1).
    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// The message that was signed, taken from `wire` where `record` is: the TSIG removed, the count decremented
    /// and the ID the original one (RFC 8945 §4.3.2).
    pub(crate) fn stripped(&mut self, wire: &[u8], record: &TsigRecord<'_>) {
        let (head, body) = wire[..record.start].split_at(HEADER_LEN);
        let mut header = [0; HEADER_LEN];
        header.copy_from_slice(head);
        header[..2].copy_from_slice(&record.tsig.original_id.to_be_bytes());
        let additional = u16::from_be_bytes([header[10], header[11]]).saturating_sub(1);
        header[10..12].copy_from_slice(&additional.to_be_bytes());
        self.0.update(&header);
        self.0.update(body);
    }

    /// The TSIG variables (RFC 8945 §4.3.3).
    pub(crate) fn variables(&mut self, owner: &Name<'_>, tsig: &Tsig<'_>) {
        let mut buf = [0; MAX_NAME_LEN];
        self.0.update(canonical(owner, &mut buf));
        self.0.update(&Class::ANY.0.to_be_bytes());
        self.0.update(&0_u32.to_be_bytes());
        self.0.update(canonical(&tsig.algorithm, &mut buf));
        self.timers(tsig.time_signed(), tsig.fudge);
        self.0.update(&tsig.error.0.to_be_bytes());
        // Other Data has at most 6 bytes where this crate signs, and at most 65535 where it checks.
        self.0.update(
            &u16::try_from(tsig.other().len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        self.0.update(tsig.other());
    }

    /// The TSIG timers (RFC 8945 §4.3.3.1).
    pub(crate) fn timers(&mut self, time_signed: u64, fudge: u16) {
        self.0.update(&time_signed.to_be_bytes()[2..]);
        self.0.update(&fudge.to_be_bytes());
    }

    pub(crate) fn finish(self) -> hmac::Tag {
        self.0.sign()
    }
}

// `ring`'s context is not `Debug`, and holds no secret worth showing.
impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Digest")
    }
}

/// Whether `received`, possibly truncated, is the start of `computed`, in constant time. A MAC under 10 bytes never
/// matches (RFC 8945 §5.2.2.1).
pub(crate) fn matches(computed: &hmac::Tag, received: &[u8]) -> bool {
    let computed = computed.as_ref();
    received.len() >= MIN_MAC_LEN
        && computed
            .get(..received.len())
            .is_some_and(|prefix| bool::from(prefix.ct_eq(received)))
}

/// What a signature is made of besides the message.
pub(crate) struct Signature<'a> {
    pub(crate) time_signed: u64,
    pub(crate) fudge: u16,
    pub(crate) error: TsigError,
    pub(crate) other: &'a [u8],
    /// The second and later messages of a stream take the timers alone (RFC 8945 §5.3.1).
    pub(crate) timers_only: bool,
}

/// Signs `wire` in place with `key`, from `digest` that holds the request MAC where there is one, and returns the
/// MAC.
pub(crate) fn sign(
    key: &Key,
    mut digest: Digest,
    wire: &mut Vec<u8>,
    signature: &Signature<'_>,
) -> Result<Vec<u8>, SignError> {
    let id = original_id(wire)?;
    digest.bytes(wire);
    let template = Tsig::new(
        key.algorithm().name(),
        signature.time_signed,
        signature.fudge,
        &[],
        id,
        signature.error,
        signature.other,
    )?;
    if signature.timers_only {
        digest.timers(signature.time_signed, signature.fudge);
    } else {
        digest.variables(key.name(), &template);
    }
    let mac = digest.finish().as_ref().to_vec();
    let tsig = Tsig::new(
        template.algorithm,
        signature.time_signed,
        signature.fudge,
        &mac,
        id,
        signature.error,
        signature.other,
    )?;
    append(wire, key.name(), &tsig)?;
    Ok(mac)
}

/// The ID of the message in `wire`, the Original ID of its TSIG.
pub(crate) fn original_id(wire: &[u8]) -> Result<u16, SignError> {
    match wire {
        [a, b, _, _, _, _, _, _, _, _, _, _, ..] => Ok(u16::from_be_bytes([*a, *b])),
        _ => Err(SignError::Header),
    }
}

/// Appends the TSIG record, named `owner` with class `ANY` and TTL 0 (RFC 8945 §4.2), as the last additional
/// record, counting it.
pub(crate) fn append(
    wire: &mut Vec<u8>,
    owner: &Name<'_>,
    tsig: &Tsig<'_>,
) -> Result<(), SignError> {
    original_id(wire)?;
    let additional = u16::from_be_bytes([wire[10], wire[11]])
        .checked_add(1)
        .ok_or(SignError::Count)?;
    let rdata = tsig.to_wire();
    let rdata_len = u16::try_from(rdata.len()).map_err(|_| SignError::TooLong)?;
    let mut name = [0; MAX_NAME_LEN];
    let owner = owner.to_wire(&mut name);
    if wire.len() + owner.len() + 10 + rdata.len() > MAX_MESSAGE_LEN {
        return Err(SignError::TooLong);
    }
    wire[10..12].copy_from_slice(&additional.to_be_bytes());
    wire.extend_from_slice(owner);
    wire.extend_from_slice(&RecordType::TSIG.0.to_be_bytes());
    wire.extend_from_slice(&Class::ANY.0.to_be_bytes());
    wire.extend_from_slice(&0_u32.to_be_bytes());
    wire.extend_from_slice(&rdata_len.to_be_bytes());
    wire.extend_from_slice(&rdata);
    Ok(())
}
