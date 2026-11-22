//! The serde field codecs of the capture files (`recursion`, `authoritative`): `#[serde(with = "text")]` for a value
//! in its presentation form, `#[serde(with = "base64")]` for bytes.

/// A field in its presentation form, as `Display` writes it and `FromStr` reads it.
pub(crate) mod text {
    use std::fmt::Display;
    use std::str::FromStr;

    use serde::Deserialize;

    pub(crate) fn serialize<T: Display, S: serde::Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub(crate) fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr<Err: Display>,
        D: serde::Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Bytes in base64 (RFC 4648 §4).
pub(crate) mod base64 {
    use data_encoding::BASE64;
    use serde::Deserialize;

    pub(crate) fn serialize<S: serde::Serializer>(
        bytes: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
