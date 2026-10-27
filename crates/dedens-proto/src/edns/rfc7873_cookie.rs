//! COOKIE option (RFC 7873 §4).

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::wire::{Reader, Writer};

/// A server cookie that is not 8 to 32 bytes (RFC 7873 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("server cookie must be 8 to 32 bytes")]
pub struct InvalidServerCookie;

/// A client cookie of 8 bytes, with the server cookie of 8 to 32 bytes once a server has sent one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cookie {
    client: [u8; 8],
    server: Option<Box<[u8]>>,
}

impl Cookie {
    /// A cookie.
    ///
    /// # Errors
    ///
    /// [`InvalidServerCookie`] when `server` is present and not 8 to 32 bytes.
    pub fn new(client: [u8; 8], server: Option<&[u8]>) -> Result<Self, InvalidServerCookie> {
        if server.is_some_and(|s| !(8..=32).contains(&s.len())) {
            return Err(InvalidServerCookie);
        }
        Ok(Self {
            client,
            server: server.map(Into::into),
        })
    }

    /// The client cookie.
    #[must_use]
    pub const fn client(&self) -> [u8; 8] {
        self.client
    }

    /// The server cookie, absent in a first query.
    #[must_use]
    pub fn server(&self) -> Option<&[u8]> {
        self.server.as_deref()
    }

    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let client = r.array::<8>()?;
        let server = r.rest();
        Self::new(client, (!server.is_empty()).then_some(server)).map_err(|_| {
            r.error(DecodeErrorKind::Invalid(
                "server cookie must be 8 to 32 bytes",
            ))
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&self.client)?;
        w.put_bytes(self.server().unwrap_or_default())
    }
}
