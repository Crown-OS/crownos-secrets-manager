use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::Path;

use rustix::fs::{Mode, OFlags};

use crate::VaultError;

const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The file bytes, after checks that the path is a regular file, not a symbolic link, and that
/// only the owner can use it. `O_NONBLOCK` keeps a FIFO at the path from stopping the daemon.
pub(crate) fn read_private(path: &Path) -> Result<Vec<u8>, VaultError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let descriptor = rustix::fs::open(path, flags, Mode::empty())
        .map_err(|errno| VaultError::io(path)(errno.into()))?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(VaultError::io(path))?;
    if !metadata.is_file() {
        return Err(VaultError::NotARegularFile(path.to_owned()));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(VaultError::WrongOwner(path.to_owned()));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(VaultError::UnsafePermissions(path.to_owned()));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(VaultError::FileTooLarge(path.to_owned()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(VaultError::io(path))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(VaultError::FileTooLarge(path.to_owned()));
    }
    Ok(bytes)
}

/// Replaces `path` with `bytes` so a reader sees the old or the new file, never a part. The
/// directory gets mode 0700 on each write, also when it was there before.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let directory = path.parent().unwrap_or(Path::new("."));
    DirBuilder::new()
        .recursive(true)
        .mode(PRIVATE_DIRECTORY_MODE)
        .create(directory)
        .and_then(|()| {
            std::fs::set_permissions(directory, Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
        })
        .map_err(VaultError::io(directory))?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let temporary = directory.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let written = write_and_sync(&temporary, bytes)
        .and_then(|()| std::fs::rename(&temporary, path))
        .and_then(|()| File::open(directory)?.sync_all());
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.map_err(VaultError::io(path))
}

fn write_and_sync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
