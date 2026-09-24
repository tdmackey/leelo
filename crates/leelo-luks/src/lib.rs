//! This crate supplies a limited LUKS2 interface. The FFI boundary needs an audit and is not formally verified.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum Error {
    UnsupportedPlatform,
    Io(std::io::Error),
    InvalidInput,
    Cryptsetup {
        operation: &'static str,
        code: i32,
    },
    WrongVolume,
    OccupiedSlot,
    InvalidToken,
    ReadOnly,
    WriterBusy,
    NoTokenSpace,
    MetadataSpace {
        required: usize,
        available: usize,
    },
    MetadataChanged,
    PartialEnrollment {
        slot: u8,
        stage: &'static str,
        source: Box<Error>,
    },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PartialEnrollment {
                slot,
                stage,
                source,
            } => write!(
                f,
                "LUKS2 slot {slot} needs reconciliation after {stage}: {source}"
            ),
            _ => write!(f, "LUKS2: {self:?}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::PartialEnrollment { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    #[serde(rename = "type")]
    kind: String,
    keyslots: Vec<String>,
    envelope: String,
}
pub struct TokenEnvelope {
    pub slot: u8,
    pub bytes: Vec<u8>,
}
pub fn encode_token(slot: u8, envelope: &[u8]) -> Result<String, Error> {
    if slot >= 32 || envelope.is_empty() || envelope.len() > 64 * 1024 {
        return Err(Error::InvalidInput);
    }
    serde_json::to_string(&Token {
        kind: "leelo".into(),
        keyslots: vec![slot.to_string()],
        envelope: URL_SAFE_NO_PAD.encode(envelope),
    })
    .map_err(|_| Error::InvalidToken)
}
pub fn decode_token(json: &str) -> Result<TokenEnvelope, Error> {
    if json.len() > 90 * 1024 {
        return Err(Error::InvalidToken);
    }
    let t: Token = serde_json::from_str(json).map_err(|_| Error::InvalidToken)?;
    if t.kind != "leelo" || t.keyslots.len() != 1 {
        return Err(Error::InvalidToken);
    }
    let slot: u8 = t.keyslots[0].parse().map_err(|_| Error::InvalidToken)?;
    if slot >= 32 || slot.to_string() != t.keyslots[0] {
        return Err(Error::InvalidToken);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(&t.envelope)
        .map_err(|_| Error::InvalidToken)?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 || URL_SAFE_NO_PAD.encode(&bytes) != t.envelope {
        return Err(Error::InvalidToken);
    }
    Ok(TokenEnvelope { slot, bytes })
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Luks2;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_rejects_ambiguous_or_wrong_slot_fields() {
        let encoded = encode_token(3, b"signed-envelope").unwrap();
        let token = decode_token(&encoded).unwrap();
        assert_eq!(token.slot, 3);
        assert_eq!(token.bytes, b"signed-envelope");
        for invalid in [
            encoded.replace("\"leelo\"", "\"clevis\""),
            encoded.replace("[\"3\"]", "[\"3\",\"4\"]"),
            encoded.replace("[\"3\"]", "[\"03\"]"),
            encoded.replace("\"type\":", "\"type\":\"leelo\",\"type\":"),
        ] {
            assert!(decode_token(&invalid).is_err());
        }
    }
}
