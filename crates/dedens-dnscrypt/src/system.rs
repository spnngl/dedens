//! The encryption systems, `<es-version>` (draft "Certificates").

/// A classical encryption system. Both share X25519 and a Poly1305 tag over the ciphertext; they differ in the
/// stream cipher and in the derivation of the shared key (draft "Certificates", "Appendix 1: The Box-XChaChaPoly Algorithm"; for `0x0001` the 2023 text of the protocol, `docs/rfc/archive/dnscrypt-v2-protocol.txt`).
///
/// `X-Wing` (`<es-version>` 0x0003) is not here: a certificate of that system is skipped, as one of any system
/// this crate does not implement (draft "Certificates").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionSystem {
    /// `<es-version>` 0x0001, `X25519-XSalsa20Poly1305` (the 2013 `NaCl` `crypto_box`), kept by older resolvers.
    XSalsa20Poly1305,
    /// `<es-version>` 0x0002, `X25519-XChaCha20Poly1305`.
    XChaCha20Poly1305,
}

impl EncryptionSystem {
    /// The two bytes of a certificate.
    #[must_use]
    pub const fn es_version(self) -> [u8; 2] {
        match self {
            Self::XSalsa20Poly1305 => [0, 1],
            Self::XChaCha20Poly1305 => [0, 2],
        }
    }

    /// The system an `<es-version>` names, if this crate implements it.
    #[must_use]
    pub const fn from_es_version(es_version: [u8; 2]) -> Option<Self> {
        match es_version {
            [0, 1] => Some(Self::XSalsa20Poly1305),
            [0, 2] => Some(Self::XChaCha20Poly1305),
            _ => None,
        }
    }
}

/// Which systems a client accepts when it picks among certificates (draft "Certificates").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SystemPolicy {
    /// Either, `XChaCha20` before `XSalsa20`.
    #[default]
    Preferred,
    /// This one only: a certificate of the other is never used.
    Only(EncryptionSystem),
}

impl SystemPolicy {
    /// How much `system` is wanted, higher first; `None` when refused.
    pub(crate) fn rank(self, system: EncryptionSystem) -> Option<u8> {
        match (self, system) {
            (Self::Preferred, EncryptionSystem::XChaCha20Poly1305) => Some(1),
            (Self::Preferred, EncryptionSystem::XSalsa20Poly1305) => Some(0),
            (Self::Only(only), system) if only == system => Some(0),
            (Self::Only(_), _) => None,
        }
    }
}
