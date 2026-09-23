//! This module opens each secret file once. It does not follow a final symlink.
//! It checks descriptor metadata before a read with a size limit.
//! Parent paths must be trusted.
use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use zeroize::Zeroizing;

pub fn read(path: &Path, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > limit as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret file must be owned by this UID, regular, and inaccessible to group/other",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret file exceeds size limit",
        ));
    }
    Ok(bytes)
}
