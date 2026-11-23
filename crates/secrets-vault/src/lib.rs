//! The encrypted vault file of the CrownOS secrets manager, `$XDG_DATA_HOME/crownos/secrets.vault`.
//!
//! A 57-byte header holds the format version, the Argon2id parameters and salt, and the
//! XChaCha20-Poly1305 nonce. One AEAD seal covers the whole body, with the header as associated
//! data. Values live in memory only in [`secrecy::SecretBox`] types, which zero them on drop.

mod error;
mod file;
mod format;
mod kdf;
mod open_vault;
mod util;
mod vault;

pub use error::VaultError;
pub use kdf::KdfParams;
pub use open_vault::OpenVault;
pub use vault::Vault;

pub use secrets_core::MAX_VALUE_BYTES;
