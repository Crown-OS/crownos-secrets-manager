use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::{KdfParams, OpenVault, VaultError};

struct Unlocked {
    contents: OpenVault,
    lock_at: Instant,
}

/// The vault file with its lock state. An unlock lasts `lock_after_minutes` from the sealed
/// settings; then the decrypted values, rules and key are dropped and zeroed.
pub struct Vault {
    path: PathBuf,
    kdf: KdfParams,
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
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            kdf: KdfParams::default(),
            unlocked: None,
        }
    }

    /// The parameters for a vault that [`Self::init`] creates.
    #[must_use]
    pub const fn with_kdf_params(mut self, kdf: KdfParams) -> Self {
        self.kdf = kdf;
        self
    }

    pub fn exists(&self) -> bool {
        self.path.symlink_metadata().is_ok()
    }

    /// Creates an empty vault and leaves it unlocked.
    ///
    /// # Errors
    ///
    /// Fails when a vault exists, or on a write error.
    pub fn init(&mut self, password: &[u8], now: Instant) -> Result<(), VaultError> {
        let contents = OpenVault::create(&self.path, password, self.kdf)?;
        self.keep_unlocked(contents, now);
        Ok(())
    }

    /// # Errors
    ///
    /// Fails when no vault exists, on a wrong password, or on any [`OpenVault::open`] error.
    pub fn unlock(&mut self, password: &[u8], now: Instant) -> Result<(), VaultError> {
        if !self.exists() {
            return Err(VaultError::Missing);
        }
        let contents = OpenVault::open(&self.path, password)?;
        self.keep_unlocked(contents, now);
        Ok(())
    }

    /// The open vault, after a check of the master password: it unlocks a locked vault, and
    /// compares the password with the key of an unlocked one.
    ///
    /// # Errors
    ///
    /// Fails on a wrong password, or as [`Self::unlock`].
    pub fn authorize(
        &mut self,
        password: &[u8],
        now: Instant,
    ) -> Result<&mut OpenVault, VaultError> {
        self.lock_if_expired(now);
        match self.unlocked.as_ref() {
            Some(unlocked) if !unlocked.contents.password_matches(password)? => {
                return Err(VaultError::WrongPassword);
            }
            Some(_) => {}
            None => self.unlock(password, now)?,
        }
        self.contents_mut(now)
    }

    fn keep_unlocked(&mut self, contents: OpenVault, now: Instant) {
        let minutes = contents.rules().settings.lock_after_minutes;
        self.unlocked = Some(Unlocked {
            contents,
            lock_at: now + Duration::from_secs(u64::from(minutes) * 60),
        });
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
