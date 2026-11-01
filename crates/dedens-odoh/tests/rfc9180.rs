//! RFC 9180 Appendix A.1.1: the base-mode vectors of DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM,
//! run through the suite of RFC 9230 §9 as `dedens_odoh::suite` names it.

mod common;

use common::{Replay, hex};
use dedens_odoh::suite::{AEAD_ID, Aead, KDF_ID, KEM_ID, Kdf, Kem};
use hpke::{Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _};

const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
const IKM_E: &str = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
const PK_EM: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
const IKM_R: &str = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037";
const PK_RM: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
const SK_RM: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
const PLAINTEXT: &str = "4265617574792069732074727574682c20747275746820626561757479";

/// `(sequence number, ct)` of A.1.1.1.
const SEALED: [(u32, &str); 6] = [
    (
        0,
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
    ),
    (
        1,
        "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
    ),
    (
        2,
        "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
    ),
    (
        4,
        "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d",
    ),
    (
        255,
        "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a",
    ),
    (
        256,
        "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2",
    ),
];

/// `(exporter_context, exported_value)` of A.1.1.2, `L` 32.
const EXPORTED: [(&str, &str); 3] = [
    (
        "",
        "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
    ),
    (
        "00",
        "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
    ),
    (
        "54657374436f6e74657874",
        "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931",
    ),
];

fn aad(sequence: u32) -> Vec<u8> {
    format!("Count-{sequence}").into_bytes()
}

#[test]
fn suite_ids_are_those_of_rfc_9230_section_9() {
    assert_eq!((KEM_ID, KDF_ID, AEAD_ID), (0x0020, 0x0001, 0x0001));
}

#[test]
fn key_derivation() {
    // The crate serializes a private key clamped (RFC 7748 §5); the vectors keep the bytes DeriveKeyPair
    // produced. Both give the public key, which is what the vectors must agree on.
    let (_, pk) = Kem::derive_keypair(&hex(IKM_R));
    assert_eq!(pk.to_bytes().as_slice(), hex(PK_RM));
    let (_, pk) = Kem::derive_keypair(&hex(IKM_E));
    assert_eq!(pk.to_bytes().as_slice(), hex(PK_EM));
}

#[test]
fn sender_reproduces_the_vectors() {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&hex(PK_RM)).expect("32 bytes");
    let (enc, mut sender) = hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &hex(INFO),
        &mut Replay::new(&hex(IKM_E)),
    )
    .expect("sets up");
    assert_eq!(enc.to_bytes().as_slice(), hex(PK_EM));

    for sequence in 0..=256 {
        let sealed = sender.seal(&hex(PLAINTEXT), &aad(sequence)).expect("seals");
        if let Some((_, expected)) = SEALED.iter().find(|(number, _)| *number == sequence) {
            assert_eq!(sealed, hex(expected), "sequence {sequence}");
        }
    }
}

#[test]
fn exports() {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&hex(PK_RM)).expect("32 bytes");
    let (_, sender) = hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &hex(INFO),
        &mut Replay::new(&hex(IKM_E)),
    )
    .expect("sets up");
    for (context, expected) in EXPORTED {
        let mut out = [0; 32];
        sender.export(&hex(context), &mut out).expect("exports");
        assert_eq!(out.as_slice(), hex(expected), "context {context:?}");
    }
}

#[test]
fn receiver_opens_the_vectors() {
    let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(&hex(SK_RM)).expect("32 bytes");
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex(PK_EM)).expect("32 bytes");
    let mut receiver =
        hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, &hex(INFO))
            .expect("sets up");
    for (context, expected) in EXPORTED {
        let mut out = [0; 32];
        receiver.export(&hex(context), &mut out).expect("exports");
        assert_eq!(out.as_slice(), hex(expected));
    }
    // The receiver counts messages as the sender does: open in order, up to the one of the vectors.
    for sequence in 0..=2 {
        let (_, ct) = SEALED[usize::try_from(sequence).expect("small")];
        let opened = receiver
            .open(&hex(ct), &aad(sequence))
            .expect("authenticates");
        assert_eq!(opened, hex(PLAINTEXT));
    }
}
