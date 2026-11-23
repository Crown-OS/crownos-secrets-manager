use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::SecretName;

use crate::format::{self, Header, Records, SALT_LENGTH};
use crate::kdf::{KdfParams, VaultKey};
use crate::{MAX_VALUE_BYTES, VaultError, file};

/// The decrypted vault. Each change is written to disk before it shows in memory.
pub struct OpenVault {
    path: PathBuf,
    header: Header,
    key: VaultKey,
    records: Records,
}

impl std::fmt::Debug for OpenVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenVault")
            .field("path", &self.path)
            .field("secrets", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl OpenVault {
    /// Writes a new, empty vault.
    ///
    /// # Errors
    ///
    /// Fails when a file is already at `path`, or on a write error.
    pub fn create(path: &Path, password: &[u8], kdf: KdfParams) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.to_owned()));
        }
        let salt: [u8; SALT_LENGTH] = format::random_bytes()?;
        let vault = Self {
            path: path.to_owned(),
            header: Header::new(kdf, salt)?,
            key: kdf.derive_key(password, &salt)?,
            records: Records::new(),
        };
        vault.persist(std::iter::empty())?;
        Ok(vault)
    }

    /// # Errors
    ///
    /// Fails on a wrong password, a changed file, a file that others can read, or a read error.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self, VaultError> {
        let bytes = file::read_private(path)?;
        let (header, sealed_body) = Header::parse(&bytes)?;
        let key = header.kdf.derive_key(password, &header.salt)?;
        let records = format::open(header, &key, sealed_body)?;
        Ok(Self {
            path: path.to_owned(),
            header,
            key,
            records,
        })
    }

    pub fn contains(&self, name: &SecretName) -> bool {
        self.records.contains_key(name)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &SecretName> {
        self.records.keys()
    }

    /// The value, for the daemon code that types or injects it. No caller gets it back.
    pub fn value(&self, name: &SecretName) -> Option<&SecretSlice<u8>> {
        self.records.get(name)
    }

    /// Adds or replaces a secret.
    ///
    /// # Errors
    ///
    /// Fails when the value is too large or the write fails; the vault then stays unchanged.
    pub fn insert(&mut self, name: SecretName, value: SecretSlice<u8>) -> Result<(), VaultError> {
        if value.expose_secret().len() > MAX_VALUE_BYTES {
            return Err(VaultError::ValueTooLarge);
        }
        let others = self
            .records
            .iter()
            .filter(|(stored, _)| **stored != name)
            .map(|(stored, value)| (stored, value.expose_secret()));
        let added = std::iter::once((&name, value.expose_secret()));
        self.persist(others.chain(added))?;
        crate::util::memory_lock::keep_in_memory(value.expose_secret());
        self.records.insert(name, value);
        Ok(())
    }

    /// Returns whether the secret was there.
    ///
    /// # Errors
    ///
    /// Fails when the write fails; the vault then stays unchanged.
    pub fn remove(&mut self, name: &SecretName) -> Result<bool, VaultError> {
        if !self.records.contains_key(name) {
            return Ok(false);
        }
        let remaining = self
            .records
            .iter()
            .filter(|(stored, _)| *stored != name)
            .map(|(stored, value)| (stored, value.expose_secret()));
        self.persist(remaining)?;
        self.records.remove(name);
        Ok(true)
    }

    fn persist<'record>(
        &self,
        records: impl Iterator<Item = (&'record SecretName, &'record [u8])> + Clone,
    ) -> Result<(), VaultError> {
        let header = self.header.with_fresh_nonce()?;
        let bytes = format::seal(header, &self.key, records)?;
        file::write_atomically(&self.path, &bytes)
    }
}
