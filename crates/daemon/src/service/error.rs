use crownos_ipc::RemoteError;
use secrets_core::{CoreError, SecretName};
use secrets_protocol::error_code;
use secrets_protocol::transfer::TransferError;
use secrets_vault::VaultError;

use crate::config_store::ConfigStoreError;

/// Why a call failed. No variant carries a value.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("only the crownos-secrets CLI and the Settings app may do this")]
    NotAdmin,
    #[error("not available yet: this arrives in a later milestone")]
    Unavailable,
    #[error("the vault is locked; unlock it with `crownos-secrets unlock`")]
    Locked,
    #[error("no secret is named {0}")]
    UnknownSecret(SecretName),
    #[error(transparent)]
    Invalid(#[from] CoreError),
    #[error("too many calls; try again later")]
    RateLimited,
    #[error("vault: {0}")]
    Vault(VaultError),
    #[error("value transfer: {0}")]
    Transfer(#[from] TransferError),
    #[error(transparent)]
    Config(#[from] ConfigStoreError),
}

impl From<VaultError> for ServiceError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::Locked => Self::Locked,
            other => Self::Vault(other),
        }
    }
}

impl From<ServiceError> for RemoteError {
    fn from(error: ServiceError) -> Self {
        let code = match &error {
            ServiceError::NotAdmin => error_code::UNAUTHORIZED,
            ServiceError::Unavailable => error_code::UNAVAILABLE,
            ServiceError::Locked => error_code::LOCKED,
            ServiceError::UnknownSecret(_) => error_code::UNKNOWN_SECRET,
            ServiceError::Invalid(_) | ServiceError::Transfer(_) => error_code::INVALID_ARGUMENT,
            ServiceError::RateLimited => error_code::RATE_LIMITED,
            ServiceError::Vault(_) | ServiceError::Config(_) => error_code::VAULT,
        };
        Self::new(code, error.to_string())
    }
}
