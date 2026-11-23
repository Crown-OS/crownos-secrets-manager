use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("cannot use the vault file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("other users can read or write {0}; run `chmod 600` on it")]
    UnsafePermissions(PathBuf),
    #[error("{0} belongs to another user")]
    WrongOwner(PathBuf),
    #[error("{0} is not a regular file")]
    NotARegularFile(PathBuf),
    #[error("{0} is larger than a vault can be")]
    FileTooLarge(PathBuf),
    #[error("the file is not a CrownOS secrets vault")]
    NotAVault,
    #[error("the vault has format version {0}; this program reads version 1")]
    UnsupportedVersion(u8),
    #[error("the key derivation parameters in the vault header are out of range")]
    KdfParametersOutOfRange,
    #[error("wrong master password, or the vault file was changed")]
    WrongPasswordOrTampered,
    #[error("wrong master password")]
    WrongPassword,
    #[error("the vault body is damaged")]
    DamagedBody,
    #[error("the vault is locked")]
    Locked,
    #[error("no vault exists yet; run `crownos-secrets init`")]
    Missing,
    #[error("a vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("a value is larger than {max} bytes", max = crate::MAX_VALUE_BYTES)]
    ValueTooLarge,
    #[error("the system random number generator failed")]
    Random,
    #[error("the master password key derivation failed")]
    KeyDerivation,
    #[error("encryption failed")]
    Encryption,
}

impl VaultError {
    pub(crate) fn io(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Self {
        let path = path.into();
        move |source| Self::Io { path, source }
    }
}
