use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use crate::VaultError;

const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

/// The file bytes, after a check that only the owner can use the file.
pub(crate) fn read_private(path: &Path) -> Result<Vec<u8>, VaultError> {
    let mut file = File::open(path).map_err(VaultError::io(path))?;
    let metadata = file.metadata().map_err(VaultError::io(path))?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(VaultError::WrongOwner(path.to_owned()));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(VaultError::UnsafePermissions(path.to_owned()));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(VaultError::io(path))?;
    Ok(bytes)
}

/// Replaces `path` with `bytes` so a reader sees the old or the new file, never a part.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let directory = path.parent().unwrap_or(Path::new("."));
    DirBuilder::new()
        .recursive(true)
        .mode(PRIVATE_DIRECTORY_MODE)
        .create(directory)
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
