//! This crate supplies a limited LUKS2 interface. The FFI boundary needs an audit and is not formally verified.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum Error {
    UnsupportedPlatform,
    Io(std::io::Error),
    InvalidInput,
    Cryptsetup(i32),
    WrongVolume,
    OccupiedSlot,
    InvalidToken,
    ReadOnly,
    SlotAddedTokenFailed { slot: u8, code: i32 },
    PartialEnrollment { slot: u8, stage: &'static str },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LUKS2: {self:?}")
    }
}
impl std::error::Error for Error {}
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
mod linux {
    use super::*;
    use std::{
        ffi::{CStr, CString, c_char, c_int, c_void},
        fs::{File, OpenOptions},
        os::fd::AsRawFd,
        os::unix::fs::OpenOptionsExt,
        path::Path,
        ptr::NonNull,
    };

    #[repr(C)]
    struct CryptDevice {
        _opaque: [u8; 0],
    }
    #[link(name = "cryptsetup")]
    unsafe extern "C" {
        fn crypt_init(cd: *mut *mut CryptDevice, device: *const c_char) -> c_int;
        fn crypt_free(cd: *mut CryptDevice);
        fn crypt_load(
            cd: *mut CryptDevice,
            requested_type: *const c_char,
            params: *mut c_void,
        ) -> c_int;
        fn crypt_get_uuid(cd: *mut CryptDevice) -> *const c_char;
        fn crypt_keyslot_status(cd: *mut CryptDevice, slot: c_int) -> c_int;
        fn crypt_keyslot_add_by_passphrase(
            cd: *mut CryptDevice,
            slot: c_int,
            old: *const c_char,
            old_len: usize,
            new: *const c_char,
            new_len: usize,
        ) -> c_int;
        fn crypt_activate_by_passphrase(
            cd: *mut CryptDevice,
            name: *const c_char,
            slot: c_int,
            pass: *const c_char,
            len: usize,
            flags: u32,
        ) -> c_int;
        fn crypt_token_json_set(cd: *mut CryptDevice, token: c_int, json: *const c_char) -> c_int;
        fn crypt_token_json_get(
            cd: *mut CryptDevice,
            token: c_int,
            json: *mut *const c_char,
        ) -> c_int;
    }

    pub struct Luks2 {
        cd: NonNull<CryptDevice>,
        _file: File,
        uuid: [u8; 16],
        writable: bool,
    }
    impl Drop for Luks2 {
        fn drop(&mut self) {
            // SAFETY: A successful crypt_init supplied cd. This owner frees cd once.
            unsafe {
                crypt_free(self.cd.as_ptr());
            }
        }
    }
    impl Luks2 {
        pub fn open(path: &Path, writable: bool) -> Result<Self, Error> {
            let file = OpenOptions::new()
                .read(true)
                .write(writable)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let name = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
                .map_err(|_| Error::InvalidInput)?;
            let mut raw = std::ptr::null_mut();
            // SAFETY: The output pointer is valid. The NUL-terminated path is live.
            // The held fd pins the opened target for the full lifetime of this context.
            let status = unsafe { crypt_init(&mut raw, name.as_ptr()) };
            if status < 0 {
                return Err(Error::Cryptsetup(status));
            }
            let cd = NonNull::new(raw).ok_or(Error::InvalidInput)?;
            let mut device = Self {
                cd,
                _file: file,
                uuid: [0; 16],
                writable,
            };
            // SAFETY: The context is initialized. Null params are valid for a LUKS2 load.
            let status =
                unsafe { crypt_load(device.cd.as_ptr(), c"LUKS2".as_ptr(), std::ptr::null_mut()) };
            if status < 0 {
                return Err(Error::Cryptsetup(status));
            }
            // SAFETY: The library owns the returned UUID. The UUID remains valid while cd is live.
            let uuid = unsafe { crypt_get_uuid(device.cd.as_ptr()) };
            if uuid.is_null() {
                return Err(Error::WrongVolume);
            }
            let text = unsafe { CStr::from_ptr(uuid) }
                .to_str()
                .map_err(|_| Error::WrongVolume)?;
            device.uuid = *uuid::Uuid::parse_str(text)
                .map_err(|_| Error::WrongVolume)?
                .as_bytes();
            Ok(device)
        }
        pub fn uuid(&self) -> [u8; 16] {
            self.uuid
        }
        pub fn slots(&self) -> Vec<(u8, i32)> {
            (0..32)
                .map(|slot| {
                    // SAFETY: The context is live. The LUKS2 slot index is within its limits.
                    (slot, unsafe {
                        crypt_keyslot_status(self.cd.as_ptr(), slot as c_int)
                    })
                })
                .collect()
        }
        pub fn first_free_slot(&self) -> Result<u8, Error> {
            self.slots()
                .into_iter()
                .find(|(_, status)| *status == 1)
                .map(|(slot, _)| slot)
                .ok_or(Error::OccupiedSlot)
        }
        pub fn test_credential(
            &mut self,
            slot: Option<u8>,
            credential: &[u8],
        ) -> Result<u8, Error> {
            self.activate_inner(slot, credential, None)
        }
        pub fn activate(
            &mut self,
            slot: u8,
            credential: &[u8],
            mapping: &str,
        ) -> Result<(), Error> {
            if mapping.is_empty()
                || mapping.len() > 127
                || !mapping
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            {
                return Err(Error::InvalidInput);
            }
            self.activate_inner(Some(slot), credential, Some(mapping))
                .map(|_| ())
        }
        fn activate_inner(
            &mut self,
            slot: Option<u8>,
            credential: &[u8],
            mapping: Option<&str>,
        ) -> Result<u8, Error> {
            if slot.is_some_and(|s| s >= 32) || credential.is_empty() || credential.len() > 8192 {
                return Err(Error::InvalidInput);
            }
            let name = mapping
                .map(CString::new)
                .transpose()
                .map_err(|_| Error::InvalidInput)?;
            // SAFETY: The buffers remain live during the synchronous call.
            // A null name requests only verification. It does not activate a device-mapper mapping.
            let r = unsafe {
                crypt_activate_by_passphrase(
                    self.cd.as_ptr(),
                    name.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                    slot.map_or(-1, |s| s as c_int),
                    credential.as_ptr().cast(),
                    credential.len(),
                    0,
                )
            };
            if r < 0 {
                Err(Error::Cryptsetup(r))
            } else {
                Ok(r as u8)
            }
        }
        /// Add a new slot. Never overwrite or remove a working slot.
        /// Report an interrupted token write as an orphan that requires explicit reconciliation.
        pub fn add_enrollment(
            &mut self,
            slot: u8,
            old: &[u8],
            new: &[u8; 32],
            envelope: &[u8],
        ) -> Result<i32, Error> {
            if !self.writable {
                return Err(Error::ReadOnly);
            }
            if slot >= 32 || self.slots()[slot as usize].1 != 1 {
                return Err(Error::OccupiedSlot);
            }
            self.test_credential(None, old)?;
            // Validate the complete token before adding any slot.
            encode_token(slot, envelope)?;
            // SAFETY: All byte buffers are valid.
            // Cryptsetup serializes the individual metadata update.
            // This code does not write a volume key or raw header.
            let r = unsafe {
                crypt_keyslot_add_by_passphrase(
                    self.cd.as_ptr(),
                    slot as c_int,
                    old.as_ptr().cast(),
                    old.len(),
                    new.as_ptr().cast(),
                    new.len(),
                )
            };
            if r < 0 {
                return Err(Error::Cryptsetup(r));
            }
            self.test_credential(Some(slot), new)
                .map_err(|_| Error::PartialEnrollment {
                    slot,
                    stage: "credential-test",
                })?;
            self.attach_enrollment(slot, new, envelope)
                .map_err(|error| match error {
                    Error::SlotAddedTokenFailed { .. } | Error::PartialEnrollment { .. } => error,
                    _ => Error::PartialEnrollment {
                        slot,
                        stage: "token-attachment",
                    },
                })
        }

        /// Verify that the exact recovered credential unlocks the signed slot before you resume.
        /// This method never guesses slot ownership or removes a slot.
        pub fn attach_enrollment(
            &mut self,
            slot: u8,
            credential: &[u8; 32],
            envelope: &[u8],
        ) -> Result<i32, Error> {
            if !self.writable {
                return Err(Error::ReadOnly);
            }
            self.test_credential(Some(slot), credential)?;
            for id in 0..32 {
                if let Ok(token) = self.token(id)
                    && token.slot == slot
                    && token.bytes == envelope
                {
                    return Ok(id as i32);
                }
            }
            let json =
                CString::new(encode_token(slot, envelope)?).map_err(|_| Error::InvalidToken)?;
            // SAFETY: The JSON is valid and complete. The value -1 requests token allocation from cryptsetup.
            let token = unsafe { crypt_token_json_set(self.cd.as_ptr(), -1, json.as_ptr()) };
            if token < 0 {
                return Err(Error::SlotAddedTokenFailed { slot, code: token });
            }
            let persisted = self
                .token(token as u8)
                .map_err(|_| Error::PartialEnrollment {
                    slot,
                    stage: "token-readback",
                })?;
            if persisted.slot != slot || persisted.bytes != envelope {
                return Err(Error::PartialEnrollment {
                    slot,
                    stage: "token-mismatch",
                });
            }
            Ok(token)
        }
        pub fn token(&self, id: u8) -> Result<TokenEnvelope, Error> {
            if id >= 32 {
                return Err(Error::InvalidInput);
            }
            let mut json = std::ptr::null();
            // SAFETY: The output pointer is valid. The library owns the result until mutation.
            let r = unsafe { crypt_token_json_get(self.cd.as_ptr(), id as c_int, &mut json) };
            if r < 0 {
                return Err(Error::Cryptsetup(r));
            }
            if json.is_null() {
                return Err(Error::InvalidToken);
            }
            decode_token(
                unsafe { CStr::from_ptr(json) }
                    .to_str()
                    .map_err(|_| Error::InvalidToken)?,
            )
        }
    }
}
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
