//! This module opens each secret file once. It does not follow a final symlink.
//! It checks descriptor metadata before a read with a size limit.
//! Parent paths must be trusted.
use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use zeroize::Zeroizing;

/// Create a private file and make its data and directory entry durable.
/// A failed write leaves the new file in place for operator review.
pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "secret file needs a file name")
    })?;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = File::from(rustix::fs::open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    // Creation and directory synchronization use the same opened parent.
    let mut file = File::from(rustix::fs::openat(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    file.write_all(bytes)?;
    file.sync_all()?;
    parent.sync_all()
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn creation_is_private_and_never_replaces_a_file_or_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        write_new(&path, b"first secret").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first secret");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o077, 0);
        assert!(write_new(&path, b"replacement").is_err());
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(write_new(&link, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first secret");
    }

    #[test]
    fn creation_rejects_a_parent_that_is_not_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"not a directory").unwrap();
        assert!(write_new(&file.join("key"), b"secret").is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"not a directory");
    }
}
