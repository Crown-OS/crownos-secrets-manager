//! The bytes of the vault file.
//!
//! ```text
//! header (57 bytes, also the AEAD associated data)
//!   magic "CRSV" | version u8 = 1 | memory_kib u32 | iterations u32 | parallelism u32
//!   | salt [16] | nonce [24]
//! body: XChaCha20-Poly1305 ciphertext of (rules length u32 | rules | records), then the tag
//! rules: postcard encoding of `SecretRules`
//! record: kind u8 (0 secret, 1 internal) | name length u8 | name | value length u32 | value
//! ```
//!
//! Integers are little-endian.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::{SecretName, SecretRules};
use zeroize::Zeroizing;

use crate::VaultError;
use crate::kdf::{KdfParams, VaultKey};

const MAGIC: &[u8; 4] = b"CRSV";
const VERSION: u8 = 1;
pub(crate) const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const TAG_LENGTH: usize = 16;
pub(crate) const HEADER_LENGTH: usize = 4 + 1 + 12 + SALT_LENGTH + NONCE_LENGTH;

pub(crate) type Secrets = BTreeMap<SecretName, SecretSlice<u8>>;

/// Secret values are smaller; internal records such as the proxy CA key can be larger.
pub(crate) const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) kdf: KdfParams,
    pub(crate) salt: [u8; SALT_LENGTH],
    pub(crate) nonce: [u8; NONCE_LENGTH],
}

impl Header {
    pub(crate) fn new(kdf: KdfParams, salt: [u8; SALT_LENGTH]) -> Result<Self, VaultError> {
        Ok(Self {
            kdf,
            salt,
            nonce: random_bytes()?,
        })
    }

    pub(crate) fn with_fresh_nonce(self) -> Result<Self, VaultError> {
        Ok(Self {
            nonce: random_bytes()?,
            ..self
        })
    }

    fn to_bytes(self) -> [u8; HEADER_LENGTH] {
        let mut bytes = [0u8; HEADER_LENGTH];
        let fields = [
            MAGIC.as_slice(),
            &[VERSION],
            &self.kdf.memory_kib.to_le_bytes(),
            &self.kdf.iterations.to_le_bytes(),
            &self.kdf.parallelism.to_le_bytes(),
            &self.salt,
            &self.nonce,
        ];
        let mut offset = 0;
        for field in fields {
            if let Some(slot) = bytes.get_mut(offset..offset + field.len()) {
                slot.copy_from_slice(field);
            }
            offset += field.len();
        }
        bytes
    }

    pub(crate) fn parse(file: &[u8]) -> Result<(Self, &[u8]), VaultError> {
        let mut reader = ByteReader(file);
        if reader.take(MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(VaultError::NotAVault);
        }
        let version = reader.u8().ok_or(VaultError::NotAVault)?;
        if version != VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        let kdf = KdfParams {
            memory_kib: reader.u32().ok_or(VaultError::NotAVault)?,
            iterations: reader.u32().ok_or(VaultError::NotAVault)?,
            parallelism: reader.u32().ok_or(VaultError::NotAVault)?,
        }
        .validate_from_file()?;
        let salt = reader.array().ok_or(VaultError::NotAVault)?;
        let nonce = reader.array().ok_or(VaultError::NotAVault)?;
        Ok((Self { kdf, salt, nonce }, reader.0))
    }
}

pub(crate) fn random_bytes<const LENGTH: usize>() -> Result<[u8; LENGTH], VaultError> {
    let mut bytes = [0u8; LENGTH];
    getrandom::fill(&mut bytes).map_err(|_| VaultError::Random)?;
    Ok(bytes)
}

fn cipher(key: &VaultKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key.expose_secret()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordKind {
    Secret = 0,
    Internal = 1,
}

#[derive(Clone, Copy)]
pub(crate) struct Record<'record> {
    pub(crate) kind: RecordKind,
    pub(crate) name: &'record str,
    pub(crate) value: &'record [u8],
}

/// What the decrypted body holds.
pub(crate) struct Contents {
    pub(crate) rules: SecretRules,
    pub(crate) secrets: Secrets,
    pub(crate) internal: BTreeMap<String, SecretSlice<u8>>,
}

/// The complete file: header, then the sealed rules and records.
pub(crate) fn seal<'record>(
    header: Header,
    key: &VaultKey,
    rules: &SecretRules,
    records: impl Iterator<Item = Record<'record>> + Clone,
) -> Result<Vec<u8>, VaultError> {
    let encoded_rules = postcard::to_stdvec(rules).map_err(|_| VaultError::DamagedBody)?;
    let rules_length = u32::try_from(encoded_rules.len()).map_err(|_| VaultError::DamagedBody)?;
    let records_length: usize = records
        .clone()
        .map(|record| 1 + 1 + record.name.len() + 4 + record.value.len())
        .sum();
    let mut body = Zeroizing::new(Vec::with_capacity(
        4 + encoded_rules.len() + records_length + TAG_LENGTH,
    ));
    body.extend_from_slice(&rules_length.to_le_bytes());
    body.extend_from_slice(&encoded_rules);
    for record in records {
        let name_length = u8::try_from(record.name.len()).map_err(|_| VaultError::DamagedBody)?;
        let value_length =
            u32::try_from(record.value.len()).map_err(|_| VaultError::ValueTooLarge)?;
        body.push(record.kind as u8);
        body.push(name_length);
        body.extend_from_slice(record.name.as_bytes());
        body.extend_from_slice(&value_length.to_le_bytes());
        body.extend_from_slice(record.value);
    }
    let header_bytes = header.to_bytes();
    cipher(key)
        .encrypt_in_place(XNonce::from_slice(&header.nonce), &header_bytes, &mut *body)
        .map_err(|_| VaultError::Encryption)?;
    Ok([header_bytes.as_slice(), &body].concat())
}

pub(crate) fn open(
    header: Header,
    key: &VaultKey,
    sealed_body: &[u8],
) -> Result<Contents, VaultError> {
    let mut body = Zeroizing::new(sealed_body.to_vec());
    cipher(key)
        .decrypt_in_place(
            XNonce::from_slice(&header.nonce),
            &header.to_bytes(),
            &mut *body,
        )
        .map_err(|_| VaultError::WrongPasswordOrTampered)?;
    let mut reader = ByteReader(&body);
    let rules_length = usize::try_from(reader.u32().ok_or(VaultError::DamagedBody)?)
        .map_err(|_| VaultError::DamagedBody)?;
    let encoded_rules = reader.take(rules_length).ok_or(VaultError::DamagedBody)?;
    let rules = postcard::from_bytes(encoded_rules).map_err(|_| VaultError::DamagedBody)?;
    let mut contents = Contents {
        rules,
        secrets: Secrets::new(),
        internal: BTreeMap::new(),
    };
    while !reader.0.is_empty() {
        let kind = reader.u8().ok_or(VaultError::DamagedBody)?;
        let name_length = usize::from(reader.u8().ok_or(VaultError::DamagedBody)?);
        let name = reader.take(name_length).ok_or(VaultError::DamagedBody)?;
        let name = std::str::from_utf8(name).map_err(|_| VaultError::DamagedBody)?;
        let value_length = usize::try_from(reader.u32().ok_or(VaultError::DamagedBody)?)
            .map_err(|_| VaultError::DamagedBody)?;
        if value_length > MAX_RECORD_BYTES {
            return Err(VaultError::DamagedBody);
        }
        let value = reader.take(value_length).ok_or(VaultError::DamagedBody)?;
        let value = crate::util::memory_lock::locked_secret(value);
        match kind {
            0 => {
                let name = SecretName::parse(name).map_err(|_| VaultError::DamagedBody)?;
                contents.secrets.insert(name, value);
            }
            1 => {
                contents.internal.insert(name.to_owned(), value);
            }
            _ => return Err(VaultError::DamagedBody),
        }
    }
    Ok(contents)
}

struct ByteReader<'bytes>(&'bytes [u8]);

impl<'bytes> ByteReader<'bytes> {
    fn take(&mut self, length: usize) -> Option<&'bytes [u8]> {
        let (taken, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(taken)
    }

    fn array<const LENGTH: usize>(&mut self) -> Option<[u8; LENGTH]> {
        self.take(LENGTH)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }
}
