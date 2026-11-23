//! Where the daemon reads and writes `secrets.ron`.

use std::sync::Mutex;

use secrets_core::SecretsConfig;

#[derive(Debug, thiserror::Error)]
pub enum ConfigStoreError {
    #[error("cannot read secrets.ron: {0}")]
    Read(String),
    #[error("cannot write secrets.ron: {0}")]
    Write(#[from] std::io::Error),
}

pub trait ConfigStore {
    /// # Errors
    ///
    /// Fails when the file exists but cannot be read or parsed.
    fn load(&self) -> Result<SecretsConfig, ConfigStoreError>;

    /// # Errors
    ///
    /// Fails when the file cannot be written.
    fn save(&self, config: &SecretsConfig) -> Result<(), ConfigStoreError>;
}

/// `~/.config/crownos/secrets.ron` through crownos-config.
#[derive(Debug, Clone, Copy, Default)]
pub struct CrownosConfigStore;

impl ConfigStore for CrownosConfigStore {
    fn load(&self) -> Result<SecretsConfig, ConfigStoreError> {
        crownos_config::load_strict(SecretsConfig::SECTION)
            .map_err(|error| ConfigStoreError::Read(error.to_string()))
    }

    fn save(&self, config: &SecretsConfig) -> Result<(), ConfigStoreError> {
        crownos_config::save(SecretsConfig::SECTION, config).map_err(Into::into)
    }
}

/// A config that lives in memory only, for tests and tools.
#[derive(Debug, Default)]
pub struct MemoryConfigStore(Mutex<SecretsConfig>);

impl MemoryConfigStore {
    pub const fn new(config: SecretsConfig) -> Self {
        Self(Mutex::new(config))
    }
}

impl ConfigStore for MemoryConfigStore {
    fn load(&self) -> Result<SecretsConfig, ConfigStoreError> {
        self.0
            .lock()
            .map(|config| config.clone())
            .map_err(|_| ConfigStoreError::Read("the config lock is poisoned".into()))
    }

    fn save(&self, config: &SecretsConfig) -> Result<(), ConfigStoreError> {
        let mut stored = self
            .0
            .lock()
            .map_err(|_| ConfigStoreError::Read("the config lock is poisoned".into()))?;
        config.clone_into(&mut stored);
        Ok(())
    }
}

impl<Store: ConfigStore> ConfigStore for &Store {
    fn load(&self) -> Result<SecretsConfig, ConfigStoreError> {
        (**self).load()
    }

    fn save(&self, config: &SecretsConfig) -> Result<(), ConfigStoreError> {
        (**self).save(config)
    }
}

impl<Store: ConfigStore> ConfigStore for std::sync::Arc<Store> {
    fn load(&self) -> Result<SecretsConfig, ConfigStoreError> {
        (**self).load()
    }

    fn save(&self, config: &SecretsConfig) -> Result<(), ConfigStoreError> {
        (**self).save(config)
    }
}
