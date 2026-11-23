#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::SecretName;
use secrets_vault::{KdfParams, OpenVault, Vault, VaultError};

const FAST_KDF: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};
const PASSWORD: &[u8] = b"correct horse battery staple";

fn name(text: &str) -> SecretName {
    SecretName::parse(text).unwrap()
}

fn vault_with_two_secrets(directory: &Path) -> PathBuf {
    let path = directory.join("crownos/secrets.vault");
    let mut vault = OpenVault::create(&path, PASSWORD, FAST_KDF).unwrap();
    vault
        .insert(
            name("github_token"),
            SecretSlice::from(b"ghp_planted".to_vec()),
        )
        .unwrap();
    vault
        .insert(name("mail"), SecretSlice::from(b"hunter2".to_vec()))
        .unwrap();
    path
}

fn flip_byte(path: &Path, index_from_start: Option<usize>) {
    let mut bytes = std::fs::read(path).unwrap();
    let index = index_from_start.unwrap_or(bytes.len() - 1);
    bytes[index] ^= 0x01;
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn values_survive_a_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let vault = OpenVault::open(&path, PASSWORD).unwrap();
    assert_eq!(vault.len(), 2);
    assert_eq!(
        vault.value(&name("github_token")).unwrap().expose_secret(),
        b"ghp_planted"
    );
    assert_eq!(
        vault.value(&name("mail")).unwrap().expose_secret(),
        b"hunter2"
    );
}

#[test]
fn the_file_is_private_and_holds_no_plaintext() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let directory_mode = std::fs::metadata(path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(directory_mode & 0o777, 0o700);
    let bytes = std::fs::read(&path).unwrap();
    for plaintext in [&b"ghp_planted"[..], b"hunter2", b"github_token"] {
        assert!(
            !bytes
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }
}

#[test]
fn a_wrong_password_fails() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let error = OpenVault::open(&path, b"wrong password").unwrap_err();
    assert!(
        matches!(error, VaultError::WrongPasswordOrTampered),
        "{error}"
    );
}

#[test]
fn a_changed_header_body_or_tag_is_detected() {
    let header_salt = 4 + 1 + 12;
    let header_nonce = header_salt + 16;
    let body = 57;
    for index in [
        Some(header_salt),
        Some(header_nonce),
        Some(body),
        Some(body + 5),
        None,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = vault_with_two_secrets(directory.path());
        flip_byte(&path, index);
        let error = OpenVault::open(&path, PASSWORD).unwrap_err();
        assert!(
            matches!(error, VaultError::WrongPasswordOrTampered),
            "byte {index:?}: {error}"
        );
    }
}

#[test]
fn a_changed_version_or_magic_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    flip_byte(&path, Some(4));
    let error = OpenVault::open(&path, PASSWORD).unwrap_err();
    assert!(
        matches!(error, VaultError::UnsupportedVersion(0)),
        "{error}"
    );
    flip_byte(&path, Some(4));
    flip_byte(&path, Some(0));
    let error = OpenVault::open(&path, PASSWORD).unwrap_err();
    assert!(matches!(error, VaultError::NotAVault), "{error}");
}

#[test]
fn huge_kdf_parameters_in_the_header_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&path, bytes).unwrap();
    let error = OpenVault::open(&path, PASSWORD).unwrap_err();
    assert!(
        matches!(error, VaultError::KdfParametersOutOfRange),
        "{error}"
    );
}

#[test]
fn a_file_that_others_can_read_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    for mode in [0o640, 0o604, 0o660] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = OpenVault::open(&path, PASSWORD).unwrap_err();
        assert!(
            matches!(error, VaultError::UnsafePermissions(_)),
            "{mode:o}: {error}"
        );
    }
}

#[test]
fn removing_and_replacing_persist() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let mut vault = OpenVault::open(&path, PASSWORD).unwrap();
    assert!(vault.remove(&name("mail")).unwrap());
    assert!(!vault.remove(&name("mail")).unwrap());
    vault
        .insert(name("github_token"), SecretSlice::from(b"ghp_new".to_vec()))
        .unwrap();
    let reopened = OpenVault::open(&path, PASSWORD).unwrap();
    assert!(!reopened.contains(&name("mail")));
    assert_eq!(
        reopened
            .value(&name("github_token"))
            .unwrap()
            .expose_secret(),
        b"ghp_new"
    );
}

#[test]
fn debug_output_shows_no_value() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let vault = OpenVault::open(&path, PASSWORD).unwrap();
    let debug = format!("{vault:?}");
    assert!(
        !debug.contains("ghp_planted") && !debug.contains("hunter2"),
        "{debug}"
    );
}

#[test]
fn the_vault_locks_itself_after_the_timeout() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.vault");
    let mut vault = Vault::new(path, Duration::from_secs(60)).with_kdf_params(FAST_KDF);
    let start = Instant::now();
    assert!(matches!(vault.contents(start), Err(VaultError::Locked)));
    vault.unlock(PASSWORD, start).unwrap();
    assert!(vault.exists());
    assert!(vault.contents(start + Duration::from_secs(59)).is_ok());
    assert!(vault.locks_in(start + Duration::from_secs(30)).is_some());
    assert!(matches!(
        vault.contents(start + Duration::from_secs(60)),
        Err(VaultError::Locked)
    ));
    assert!(vault.locks_in(start).is_none());
    assert!(vault.unlock(b"another password", start).is_err());
    vault.unlock(PASSWORD, start).unwrap();
    vault.lock();
    assert!(matches!(vault.contents(start), Err(VaultError::Locked)));
}
