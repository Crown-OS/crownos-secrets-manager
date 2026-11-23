use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::{SecretEntry, SecretName, SecretRules};

use crate::format::{self, Contents, Header, Record, RecordKind, SALT_LENGTH, Secrets};
use crate::kdf::{KdfParams, VaultKey};
use crate::{MAX_VALUE_BYTES, VaultError, file};

/// One change to the records, written together with the rules.
#[derive(Clone, Copy)]
enum RecordChange<'change> {
    None,
    PutSecret(&'change SecretName, &'change [u8]),
    DropSecret(&'change SecretName),
    PutInternal(&'change str, &'change [u8]),
}

/// The decrypted vault: rules, values and internal records. Each change is written to disk
/// before it shows in memory.
pub struct OpenVault {
    path: PathBuf,
    header: Header,
    key: VaultKey,
    contents: Contents,
}

impl std::fmt::Debug for OpenVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenVault")
            .field("path", &self.path)
            .field("secrets", &self.contents.secrets.len())
            .finish_non_exhaustive()
    }
}

impl OpenVault {
    /// Writes a new vault with default rules and no secrets.
    ///
    /// # Errors
    ///
    /// Fails when a file is already at `path`, or on a write error.
    pub fn create(path: &Path, password: &[u8], kdf: KdfParams) -> Result<Self, VaultError> {
        if path.symlink_metadata().is_ok() {
            return Err(VaultError::AlreadyExists(path.to_owned()));
        }
        let salt: [u8; SALT_LENGTH] = format::random_bytes()?;
        let vault = Self {
            path: path.to_owned(),
            header: Header::new(kdf, salt)?,
            key: kdf.derive_key(password, &salt)?,
            contents: Contents {
                rules: SecretRules::default(),
                secrets: Secrets::new(),
                internal: std::collections::BTreeMap::new(),
            },
        };
        vault.persist(&vault.contents.rules, RecordChange::None)?;
        Ok(vault)
    }

    /// # Errors
    ///
    /// Fails on a wrong password, a changed file, a file that others can read, or a read error.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self, VaultError> {
        let bytes = file::read_private(path)?;
        let (header, sealed_body) = Header::parse(&bytes)?;
        let key = header.kdf.derive_key(password, &header.salt)?;
        let contents = format::open(header, &key, sealed_body)?;
        Ok(Self {
            path: path.to_owned(),
            header,
            key,
            contents,
        })
    }

    /// Whether `password` derives the key of this vault. Takes one key derivation.
    ///
    /// # Errors
    ///
    /// Fails when the key derivation fails.
    pub fn password_matches(&self, password: &[u8]) -> Result<bool, VaultError> {
        let candidate = self.header.kdf.derive_key(password, &self.header.salt)?;
        let difference = candidate
            .expose_secret()
            .iter()
            .zip(self.key.expose_secret())
            .fold(0u8, |difference, (left, right)| difference | (left ^ right));
        Ok(difference == 0)
    }

    pub const fn rules(&self) -> &SecretRules {
        &self.contents.rules
    }

    pub fn contains(&self, name: &SecretName) -> bool {
        self.contents.secrets.contains_key(name)
    }

    /// The value, for the daemon code that types or injects it. No caller gets it back.
    pub fn value(&self, name: &SecretName) -> Option<&SecretSlice<u8>> {
        self.contents.secrets.get(name)
    }

    /// A record that belongs to the daemon itself, such as the proxy CA key.
    pub fn internal(&self, key: &str) -> Option<&SecretSlice<u8>> {
        self.contents.internal.get(key)
    }

    /// Adds or replaces a secret together with its rules entry.
    ///
    /// # Errors
    ///
    /// Fails when the value is too large or the write fails; the vault then stays unchanged.
    pub fn insert_secret(
        &mut self,
        name: SecretName,
        entry: SecretEntry,
        value: SecretSlice<u8>,
    ) -> Result<(), VaultError> {
        if value.expose_secret().len() > MAX_VALUE_BYTES {
            return Err(VaultError::ValueTooLarge);
        }
        let mut rules = self.contents.rules.clone();
        rules.secrets.insert(name.clone(), entry);
        self.persist(
            &rules,
            RecordChange::PutSecret(&name, value.expose_secret()),
        )?;
        crate::util::memory_lock::keep_in_memory(value.expose_secret());
        self.contents.rules = rules;
        self.contents.secrets.insert(name, value);
        Ok(())
    }

    /// Removes a secret and its rules entry. Returns whether either was there.
    ///
    /// # Errors
    ///
    /// Fails when the write fails; the vault then stays unchanged.
    pub fn remove_secret(&mut self, name: &SecretName) -> Result<bool, VaultError> {
        let mut rules = self.contents.rules.clone();
        let had_rules = rules.secrets.remove(name).is_some();
        if !had_rules && !self.contains(name) {
            return Ok(false);
        }
        self.persist(&rules, RecordChange::DropSecret(name))?;
        self.contents.rules = rules;
        self.contents.secrets.remove(name);
        Ok(true)
    }

    /// Changes the rules and writes them.
    ///
    /// # Errors
    ///
    /// Fails when the write fails; the rules then stay unchanged.
    pub fn change_rules(
        &mut self,
        change: impl FnOnce(&mut SecretRules),
    ) -> Result<(), VaultError> {
        let mut rules = self.contents.rules.clone();
        change(&mut rules);
        self.persist(&rules, RecordChange::None)?;
        self.contents.rules = rules;
        Ok(())
    }

    /// # Errors
    ///
    /// Fails when the write fails; the vault then stays unchanged.
    pub fn set_internal(&mut self, key: &str, value: SecretSlice<u8>) -> Result<(), VaultError> {
        self.persist(
            &self.contents.rules,
            RecordChange::PutInternal(key, value.expose_secret()),
        )?;
        crate::util::memory_lock::keep_in_memory(value.expose_secret());
        self.contents.internal.insert(key.to_owned(), value);
        Ok(())
    }

    fn persist(&self, rules: &SecretRules, change: RecordChange<'_>) -> Result<(), VaultError> {
        let replaced_secret = match change {
            RecordChange::PutSecret(name, _) | RecordChange::DropSecret(name) => Some(name),
            RecordChange::None | RecordChange::PutInternal(..) => None,
        };
        let replaced_internal = match change {
            RecordChange::PutInternal(key, _) => Some(key),
            _ => None,
        };
        let secrets = self
            .contents
            .secrets
            .iter()
            .filter(move |(name, _)| Some(*name) != replaced_secret)
            .map(|(name, value)| Record {
                kind: RecordKind::Secret,
                name: name.as_str(),
                value: value.expose_secret(),
            });
        let internal = self
            .contents
            .internal
            .iter()
            .filter(move |(key, _)| Some(key.as_str()) != replaced_internal)
            .map(|(key, value)| Record {
                kind: RecordKind::Internal,
                name: key,
                value: value.expose_secret(),
            });
        let added = match change {
            RecordChange::PutSecret(name, value) => Some(Record {
                kind: RecordKind::Secret,
                name: name.as_str(),
                value,
            }),
            RecordChange::PutInternal(key, value) => Some(Record {
                kind: RecordKind::Internal,
                name: key,
                value,
            }),
            RecordChange::None | RecordChange::DropSecret(_) => None,
        };
        let header = self.header.with_fresh_nonce()?;
        let bytes = format::seal(
            header,
            &self.key,
            rules,
            secrets.chain(internal).chain(added),
        )?;
        file::write_atomically(&self.path, &bytes)
    }
}
