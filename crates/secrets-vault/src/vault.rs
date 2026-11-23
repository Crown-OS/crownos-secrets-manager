use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{KdfParams, OpenVault, VaultError};

struct Unlocked {
    contents: OpenVault,
    lock_at: Instant,
}

/// The vault file with its lock state. An unlock lasts `lock_after`; then the decrypted values
/// and the key are dropped and zeroed.
pub struct Vault {
    path: PathBuf,
    kdf: KdfParams,
    lock_after: Duration,
    unlocked: Option<Unlocked>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Vault")
            .field("path", &self.path)
            .field("unlocked", &self.unlocked.is_some())
            .finish_non_exhaustive()
    }
}

impl Vault {
    pub fn new(path: PathBuf, lock_after: Duration) -> Self {
        Self {
            path,
            kdf: KdfParams::default(),
            lock_after,
            unlocked: None,
        }
    }

    /// The parameters for a vault that [`Self::unlock`] creates.
    #[must_use]
    pub const fn with_kdf_params(mut self, kdf: KdfParams) -> Self {
        self.kdf = kdf;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub const fn set_lock_after(&mut self, lock_after: Duration) {
        self.lock_after = lock_after;
    }

    /// Opens the vault, or creates an empty one when no file exists yet.
    ///
    /// # Errors
    ///
    /// Fails on a wrong password or any [`OpenVault::open`] error.
    pub fn unlock(&mut self, password: &[u8], now: Instant) -> Result<(), VaultError> {
        let contents = if self.exists() {
            OpenVault::open(&self.path, password)?
        } else {
            OpenVault::create(&self.path, password, self.kdf)?
        };
        self.unlocked = Some(Unlocked {
            contents,
            lock_at: now + self.lock_after,
        });
        Ok(())
    }

    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    /// Returns whether this call locked the vault.
    pub fn lock_if_expired(&mut self, now: Instant) -> bool {
        let expired = self
            .unlocked
            .as_ref()
            .is_some_and(|unlocked| now >= unlocked.lock_at);
        if expired {
            self.lock();
        }
        expired
    }

    /// The time left before the vault locks, or `None` when it is locked.
    pub fn locks_in(&self, now: Instant) -> Option<Duration> {
        self.unlocked
            .as_ref()
            .and_then(|unlocked| unlocked.lock_at.checked_duration_since(now))
            .filter(|left| !left.is_zero())
    }

    /// # Errors
    ///
    /// [`VaultError::Locked`] when the vault is locked or its unlock expired.
    pub fn contents(&mut self, now: Instant) -> Result<&OpenVault, VaultError> {
        self.contents_mut(now).map(|contents| &*contents)
    }

    /// # Errors
    ///
    /// [`VaultError::Locked`] when the vault is locked or its unlock expired.
    pub fn contents_mut(&mut self, now: Instant) -> Result<&mut OpenVault, VaultError> {
        self.lock_if_expired(now);
        self.unlocked
            .as_mut()
            .map(|unlocked| &mut unlocked.contents)
            .ok_or(VaultError::Locked)
    }
}
