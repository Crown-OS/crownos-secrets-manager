use std::io::{Seek as _, SeekFrom, Write as _};
use std::os::fd::OwnedFd;

use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

/// A memfd with `value`, sealed against every change, at offset 0.
pub(crate) fn sealed_value(value: &[u8]) -> std::io::Result<OwnedFd> {
    let descriptor = memfd_create(
        "crownos-secret-value",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(value)?;
    file.seek(SeekFrom::Start(0))?;
    let descriptor = OwnedFd::from(file);
    fcntl_add_seals(
        &descriptor,
        SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
    )?;
    Ok(descriptor)
}
