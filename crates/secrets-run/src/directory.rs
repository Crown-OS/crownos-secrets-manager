use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// A canonical directory with the device and inode it had at the check. The sandbox compares
/// them again inside, so a swap after the check stops the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedDirectory {
    path: PathBuf,
    identity: String,
}

impl CheckedDirectory {
    /// # Errors
    ///
    /// Fails when the path does not resolve to a directory.
    pub fn check(path: &Path) -> std::io::Result<Self> {
        let path = path.canonicalize()?;
        let metadata = std::fs::metadata(&path)?;
        if !metadata.is_dir() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotADirectory));
        }
        Ok(Self {
            identity: format!("{}:{}", metadata.dev(), metadata.ino()),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    /// For tests: the same path with the identity of another directory.
    #[must_use]
    pub fn with_identity_of(mut self, other: &Self) -> Self {
        other.identity.clone_into(&mut self.identity);
        self
    }
}
