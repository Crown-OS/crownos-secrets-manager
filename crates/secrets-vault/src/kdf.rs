use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret as _, ExposeSecretMut as _, SecretBox};

use crate::VaultError;

pub(crate) type VaultKey = SecretBox<[u8; 32]>;

/// Argon2id cost parameters. They are stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// 64 MiB and 3 passes: about half a second on a laptop CPU.
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    /// Limits for parameters read from a file, so a changed header cannot make the daemon
    /// allocate without bound.
    pub(crate) fn validate_from_file(self) -> Result<Self, VaultError> {
        let in_range = (8..=256 * 1024).contains(&self.memory_kib)
            && (1..=8).contains(&self.iterations)
            && (1..=8).contains(&self.parallelism);
        if in_range {
            Ok(self)
        } else {
            Err(VaultError::KdfParametersOutOfRange)
        }
    }

    pub(crate) fn derive_key(self, password: &[u8], salt: &[u8]) -> Result<VaultKey, VaultError> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| VaultError::KdfParametersOutOfRange)?;
        let mut key = SecretBox::new(Box::new([0u8; 32]));
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, salt, key.expose_secret_mut())
            .map_err(|_| VaultError::KeyDerivation)?;
        crate::util::memory_lock::keep_in_memory(key.expose_secret());
        Ok(key)
    }
}
