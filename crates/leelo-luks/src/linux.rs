use super::{Error, TokenEnvelope, decode_token, encode_token};
use serde_json::Value;
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    ptr::NonNull,
};

const SLOT_COUNT: u8 = 32;
const SLOT_INACTIVE: c_int = 1;
const BINARY_HEADER_SIZE: usize = 4096;
// The new standard keyslot and its digest association also consume JSON space.
// This is a conservative reservation, not a dry run of libcryptsetup's AddKey.
const NEW_SLOT_JSON_RESERVE: usize = 4096;

#[cfg(test)]
mod tests;

#[repr(C)]
struct CryptDevice {
    _opaque: [u8; 0],
}

#[link(name = "cryptsetup")]
unsafe extern "C" {
    fn crypt_init(cd: *mut *mut CryptDevice, device: *const c_char) -> c_int;
    fn crypt_free(cd: *mut CryptDevice);
    fn crypt_load(cd: *mut CryptDevice, kind: *const c_char, params: *mut c_void) -> c_int;
    fn crypt_get_uuid(cd: *mut CryptDevice) -> *const c_char;
    fn crypt_get_metadata_size(cd: *mut CryptDevice, metadata: *mut u64, slots: *mut u64) -> c_int;
    fn crypt_dump_json(cd: *mut CryptDevice, json: *mut *const c_char, flags: u32) -> c_int;
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
    fn crypt_token_json_get(cd: *mut CryptDevice, token: c_int, json: *mut *const c_char) -> c_int;
}

fn checked(operation: &'static str, code: c_int) -> Result<c_int, Error> {
    if code < 0 {
        Err(Error::Cryptsetup { operation, code })
    } else {
        Ok(code)
    }
}

fn partial(slot: u8, stage: &'static str, source: Error) -> Error {
    Error::PartialEnrollment {
        slot,
        stage,
        source: Box::new(source),
    }
}

/// Coordinate Leelo writers without disabling libcryptsetup's metadata locks.
/// Native cryptsetup writers do not participate in this outer lock.
struct WriteLock(File);

impl WriteLock {
    fn acquire(file: &File) -> Result<Self, Error> {
        let file = file.try_clone()?;
        let lock = libc::flock {
            l_type: libc::F_WRLCK as _,
            l_whence: libc::SEEK_SET as _,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        // SAFETY: The descriptor is live. The pointer refers to an initialized flock.
        // OFD locks belong to the held open-file description, not the process.
        let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &lock) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::EAGAIN | libc::EACCES) => Error::WriterBusy,
                _ => Error::Io(error),
            });
        }
        Ok(Self(file))
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        let lock = libc::flock {
            l_type: libc::F_UNLCK as _,
            l_whence: libc::SEEK_SET as _,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        // SAFETY: The guard still owns a live descriptor and an initialized flock.
        // Closing the final descriptor also releases this lock after an error.
        unsafe { libc::fcntl(self.0.as_raw_fd(), libc::F_OFD_SETLK, &lock) };
    }
}

pub struct Luks2 {
    cd: NonNull<CryptDevice>,
    file: File,
    uuid: [u8; 16],
    writable: bool,
}

struct Metadata {
    parsed: Value,
    json_bytes: usize,
    available: usize,
}

impl Drop for Luks2 {
    fn drop(&mut self) {
        // SAFETY: A successful crypt_init supplied cd. This owner frees cd once.
        // The pinned file remains open until after this destructor returns.
        unsafe { crypt_free(self.cd.as_ptr()) };
    }
}

impl Luks2 {
    pub fn open(path: &Path, writable: bool) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(writable)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        Self::from_file(file, writable)
    }

    fn from_file(file: File, writable: bool) -> Result<Self, Error> {
        let name = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| Error::InvalidInput)?;
        let mut raw = std::ptr::null_mut();
        // SAFETY: The output pointer and NUL-terminated path are live.
        // The held descriptor pins the target for the whole context lifetime.
        checked("initialize", unsafe { crypt_init(&mut raw, name.as_ptr()) })?;
        let cd = NonNull::new(raw).ok_or(Error::InvalidInput)?;
        let mut device = Self {
            cd,
            file,
            uuid: [0; 16],
            writable,
        };
        // SAFETY: The context is initialized. Null params are valid for LUKS2.
        checked("load header", unsafe {
            crypt_load(device.cd.as_ptr(), c"LUKS2".as_ptr(), std::ptr::null_mut())
        })?;
        // SAFETY: The loaded context owns a NUL-terminated UUID string or returns null.
        let uuid = unsafe { crypt_get_uuid(device.cd.as_ptr()) };
        if uuid.is_null() {
            return Err(Error::WrongVolume);
        }
        // SAFETY: No library call mutates the context before this string is copied.
        let text = unsafe { CStr::from_ptr(uuid) }
            .to_str()
            .map_err(|_| Error::WrongVolume)?;
        device.uuid = *uuid::Uuid::parse_str(text)
            .map_err(|_| Error::WrongVolume)?
            .as_bytes();
        Ok(device)
    }

    fn reload(&mut self) -> Result<(), Error> {
        // Recreate the context. Token getters only inspect a context's cached header.
        let fresh = Self::from_file(self.file.try_clone()?, self.writable)?;
        if fresh.uuid != self.uuid {
            return Err(Error::WrongVolume);
        }
        *self = fresh;
        Ok(())
    }

    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    fn slot_status(&self, slot: u8) -> Result<c_int, Error> {
        if slot >= SLOT_COUNT {
            return Err(Error::InvalidInput);
        }
        // SAFETY: The context is live. The slot index is within LUKS2 limits.
        Ok(unsafe { crypt_keyslot_status(self.cd.as_ptr(), slot as c_int) })
    }

    pub fn first_free_slot(&mut self) -> Result<u8, Error> {
        self.reload()?;
        for slot in 0..SLOT_COUNT {
            if self.slot_status(slot)? == SLOT_INACTIVE {
                return Ok(slot);
            }
        }
        Err(Error::OccupiedSlot)
    }

    pub fn test_credential(&mut self, slot: Option<u8>, credential: &[u8]) -> Result<u8, Error> {
        self.reload()?;
        self.activate_inner(slot, credential, None)
    }

    pub fn activate(&mut self, slot: u8, credential: &[u8], mapping: &str) -> Result<(), Error> {
        if mapping.is_empty()
            || mapping.len() > 127
            || !mapping
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        self.reload()?;
        self.activate_inner(Some(slot), credential, Some(mapping))
            .map(|_| ())
    }

    fn activate_inner(
        &mut self,
        slot: Option<u8>,
        credential: &[u8],
        mapping: Option<&str>,
    ) -> Result<u8, Error> {
        if slot.is_some_and(|s| s >= SLOT_COUNT) || credential.is_empty() || credential.len() > 8192
        {
            return Err(Error::InvalidInput);
        }
        let name = mapping
            .map(CString::new)
            .transpose()
            .map_err(|_| Error::InvalidInput)?;
        // SAFETY: All byte buffers remain live during the synchronous call.
        // A null name verifies the credential without creating a mapping.
        let result = checked("check or activate credential", unsafe {
            crypt_activate_by_passphrase(
                self.cd.as_ptr(),
                name.as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                slot.map_or(-1, c_int::from),
                credential.as_ptr().cast(),
                credential.len(),
                0,
            )
        })?;
        let actual = u8::try_from(result).map_err(|_| Error::MetadataChanged)?;
        if actual >= SLOT_COUNT || slot.is_some_and(|expected| expected != actual) {
            return Err(Error::MetadataChanged);
        }
        Ok(actual)
    }

    fn metadata(&self) -> Result<Metadata, Error> {
        let mut region = 0_u64;
        let mut slots = 0_u64;
        // SAFETY: The loaded context and both output pointers are valid.
        checked("read metadata size", unsafe {
            crypt_get_metadata_size(self.cd.as_ptr(), &mut region, &mut slots)
        })?;
        let available = usize::try_from(region)
            .ok()
            .and_then(|size| size.checked_sub(BINARY_HEADER_SIZE))
            .filter(|size| *size <= 4 * 1024 * 1024)
            .ok_or(Error::WrongVolume)?;
        let mut json = std::ptr::null();
        // SAFETY: The output pointer is valid. The context owns the returned JSON string.
        checked("read metadata JSON", unsafe {
            crypt_dump_json(self.cd.as_ptr(), &mut json, 0)
        })?;
        if json.is_null() {
            return Err(Error::WrongVolume);
        }
        // SAFETY: The successful getter returns a NUL-terminated string. No intervening call invalidates it.
        let bytes = unsafe { CStr::from_ptr(json) }.to_bytes();
        let parsed = serde_json::from_slice(bytes).map_err(|_| Error::WrongVolume)?;
        Ok(Metadata {
            parsed,
            json_bytes: bytes.len(),
            available,
        })
    }

    fn token_plan(
        &self,
        slot: u8,
        envelope: &[u8],
        adding_slot: bool,
    ) -> Result<(u8, CString), Error> {
        let json = encode_token(slot, envelope)?;
        let metadata = self.metadata()?;
        let tokens = metadata
            .parsed
            .get("tokens")
            .and_then(Value::as_object)
            .ok_or(Error::WrongVolume)?;
        let id = (0..SLOT_COUNT)
            .find(|id| !tokens.contains_key(&id.to_string()))
            .ok_or(Error::NoTokenSpace)?;
        // Retain the library's original JSON length, including any formatting space.
        // Reserialization can shorten foreign token numbers that json-c preserves.
        // The new member adds its quoted ID, colon, optional comma, and terminating NUL.
        let mut required = metadata.json_bytes + json.len() + id.to_string().len() + 5;
        if adding_slot {
            required += NEW_SLOT_JSON_RESERVE;
        }
        if required > metadata.available {
            return Err(Error::MetadataSpace {
                required,
                available: metadata.available,
            });
        }
        Ok((id, CString::new(json).map_err(|_| Error::InvalidToken)?))
    }

    /// Add a new slot and token. Keep all existing recovery slots.
    /// Retain the pending bundle if an error reports partial enrollment.
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
        let _lock = WriteLock::acquire(&self.file)?;
        self.reload()?;
        if self.slot_status(slot)? != SLOT_INACTIVE {
            return Err(Error::OccupiedSlot);
        }
        self.activate_inner(None, old, None)?;
        self.token_plan(slot, envelope, true)?;
        // SAFETY: The context and borrowed credentials remain live. The target slot is empty.
        // Libcryptsetup keeps its metadata locks and detects conflicting native writes.
        let result = unsafe {
            crypt_keyslot_add_by_passphrase(
                self.cd.as_ptr(),
                slot as c_int,
                old.as_ptr().cast(),
                old.len(),
                new.as_ptr().cast(),
                new.len(),
            )
        };
        if result < 0 {
            let error = Error::Cryptsetup {
                operation: "add slot",
                code: result,
            };
            // A failed write can still leave persistent state. Never guess or remove a slot.
            match self.reload().and_then(|()| self.slot_status(slot)) {
                Ok(SLOT_INACTIVE) => return Err(error),
                _ => return Err(partial(slot, "slot write", error)),
            }
        }
        if result != c_int::from(slot) {
            return Err(partial(slot, "slot identity", Error::MetadataChanged));
        }
        self.file
            .sync_all()
            .map_err(|error| partial(slot, "slot sync", error.into()))?;
        self.attach_locked(slot, new, envelope)
            .map_err(|error| partial(slot, "token attachment", error))
    }

    /// Test the exact signed slot before token attachment. Never infer ownership from an empty slot.
    pub fn attach_enrollment(
        &mut self,
        slot: u8,
        credential: &[u8; 32],
        envelope: &[u8],
    ) -> Result<i32, Error> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        let _lock = WriteLock::acquire(&self.file)?;
        self.attach_locked(slot, credential, envelope)
    }

    fn attach_locked(
        &mut self,
        slot: u8,
        credential: &[u8; 32],
        envelope: &[u8],
    ) -> Result<i32, Error> {
        self.reload()?;
        self.activate_inner(Some(slot), credential, None)?;
        let metadata = self.metadata()?;
        let tokens = metadata
            .parsed
            .get("tokens")
            .and_then(Value::as_object)
            .ok_or(Error::WrongVolume)?;
        for id in 0..SLOT_COUNT {
            if let Some(value) = tokens.get(&id.to_string()) {
                let json = serde_json::to_string(value).map_err(|_| Error::InvalidToken)?;
                if let Ok(token) = decode_token(&json)
                    && token.slot == slot
                    && token.bytes == envelope
                {
                    self.verify_persisted(id, slot, credential, envelope)?;
                    return Ok(c_int::from(id));
                }
            }
        }
        let (id, json) = self.token_plan(slot, envelope, false)?;
        // SAFETY: The live context owns the target. The JSON is NUL-terminated and valid.
        // Allocate instead of replacing an ID. A concurrent writer must not lose its token.
        let result = checked("write token", unsafe {
            crypt_token_json_set(self.cd.as_ptr(), -1, json.as_ptr())
        })
        .map_err(|error| partial(slot, "token write", error))?;
        if result != c_int::from(id) {
            return Err(partial(slot, "token identity", Error::MetadataChanged));
        }
        self.file
            .sync_all()
            .map_err(|error| partial(slot, "token sync", error.into()))?;
        self.verify_persisted(id, slot, credential, envelope)
            .map_err(|error| partial(slot, "token readback", error))?;
        Ok(result)
    }

    fn verify_persisted(
        &mut self,
        id: u8,
        slot: u8,
        credential: &[u8; 32],
        envelope: &[u8],
    ) -> Result<(), Error> {
        self.reload()?;
        let token = self.cached_token(id)?;
        if token.slot != slot || token.bytes != envelope {
            return Err(Error::MetadataChanged);
        }
        self.activate_inner(Some(slot), credential, None)?;
        Ok(())
    }

    pub fn token(&mut self, id: u8) -> Result<TokenEnvelope, Error> {
        self.reload()?;
        self.cached_token(id)
    }

    fn cached_token(&self, id: u8) -> Result<TokenEnvelope, Error> {
        if id >= SLOT_COUNT {
            return Err(Error::InvalidInput);
        }
        let mut json = std::ptr::null();
        // SAFETY: The output pointer is valid. The context owns the result until mutation.
        checked("read token", unsafe {
            crypt_token_json_get(self.cd.as_ptr(), id as c_int, &mut json)
        })?;
        if json.is_null() {
            return Err(Error::InvalidToken);
        }
        // SAFETY: No library call invalidates this NUL-terminated string before parsing finishes.
        decode_token(
            unsafe { CStr::from_ptr(json) }
                .to_str()
                .map_err(|_| Error::InvalidToken)?,
        )
    }
}
