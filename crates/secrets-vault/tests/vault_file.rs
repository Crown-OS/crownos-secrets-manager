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
use secrets_core::{Binding, SecretEntry, SecretKind, SecretName};
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

fn entry(agent: &str) -> SecretEntry {
    SecretEntry {
        kind: SecretKind::Token,
        binding: Binding {
            agents: vec![agent.into()],
            ..Binding::default()
        },
    }
}

fn secret(value: &[u8]) -> SecretSlice<u8> {
    SecretSlice::from(value.to_vec())
}

fn vault_with_two_secrets(directory: &Path) -> PathBuf {
    let path = directory.join("crownos/secrets.vault");
    let mut vault = OpenVault::create(&path, PASSWORD, FAST_KDF).unwrap();
    vault
        .insert_secret(
            name("github_token"),
            entry("/opt/agent-one"),
            secret(b"ghp_planted"),
        )
        .unwrap();
    vault
        .insert_secret(name("mail"), entry("/opt/agent-two"), secret(b"hunter2"))
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
    assert_eq!(vault.rules().secrets.len(), 2);
    assert_eq!(
        vault.rules().secrets[&name("mail")],
        entry("/opt/agent-two")
    );
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
    for plaintext in [
        &b"ghp_planted"[..],
        b"hunter2",
        b"github_token",
        b"/opt/agent-one",
    ] {
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
fn a_symbolic_link_or_a_fifo_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let link = directory.path().join("link.vault");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(OpenVault::open(&link, PASSWORD).is_err());
    let fifo = directory.path().join("fifo.vault");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .unwrap();
    let error = OpenVault::open(&fifo, PASSWORD).unwrap_err();
    assert!(matches!(error, VaultError::NotARegularFile(_)), "{error}");
}

#[test]
fn each_write_makes_the_directory_private_again() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let parent = path.parent().unwrap();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut vault = OpenVault::open(&path, PASSWORD).unwrap();
    vault
        .change_rules(|rules| rules.settings.lock_after_minutes = 5)
        .unwrap();
    let mode = std::fs::metadata(parent).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[test]
fn removing_replacing_and_rule_changes_persist() {
    let directory = tempfile::tempdir().unwrap();
    let path = vault_with_two_secrets(directory.path());
    let mut vault = OpenVault::open(&path, PASSWORD).unwrap();
    assert!(vault.remove_secret(&name("mail")).unwrap());
    assert!(!vault.remove_secret(&name("mail")).unwrap());
    vault
        .insert_secret(
            name("github_token"),
            entry("/opt/agent-one"),
            secret(b"ghp_new"),
        )
        .unwrap();
    vault
        .change_rules(|rules| rules.settings.lock_after_minutes = 3)
        .unwrap();
    vault
        .set_internals(vec![
            ("proxy-ca-key", secret(b"ca key")),
            ("other", secret(b"x")),
        ])
        .unwrap();
    let reopened = OpenVault::open(&path, PASSWORD).unwrap();
    assert!(!reopened.contains(&name("mail")));
    assert!(!reopened.rules().secrets.contains_key(&name("mail")));
    assert_eq!(reopened.rules().settings.lock_after_minutes, 3);
    assert_eq!(
        reopened.internal("proxy-ca-key").unwrap().expose_secret(),
        b"ca key"
    );
    assert_eq!(reopened.internal("other").unwrap().expose_secret(), b"x");
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
fn the_password_is_checked_on_each_authorization() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.vault");
    let mut vault = Vault::new(path).with_kdf_params(FAST_KDF);
    let start = Instant::now();
    assert!(matches!(
        vault.unlock(PASSWORD, start),
        Err(VaultError::Missing)
    ));
    vault.init(PASSWORD, start).unwrap();
    assert!(matches!(
        vault.init(PASSWORD, start),
        Err(VaultError::AlreadyExists(_))
    ));
    assert!(matches!(
        vault.authorize(b"wrong", start),
        Err(VaultError::WrongPassword)
    ));
    assert!(vault.authorize(PASSWORD, start).is_ok());
    vault.lock();
    assert!(matches!(
        vault.authorize(b"wrong", start),
        Err(VaultError::WrongPasswordOrTampered)
    ));
    assert!(vault.authorize(PASSWORD, start).is_ok());
}

#[test]
fn the_vault_locks_itself_after_the_sealed_timeout() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.vault");
    let mut vault = Vault::new(path).with_kdf_params(FAST_KDF);
    let start = Instant::now();
    assert!(matches!(vault.contents(start), Err(VaultError::Locked)));
    vault.init(PASSWORD, start).unwrap();
    vault
        .contents_mut(start)
        .unwrap()
        .change_rules(|rules| rules.settings.lock_after_minutes = 1)
        .unwrap();
    vault.lock();
    vault.unlock(PASSWORD, start).unwrap();
    assert!(vault.contents(start + Duration::from_secs(59)).is_ok());
    assert!(vault.locks_in(start + Duration::from_secs(30)).is_some());
    assert!(matches!(
        vault.contents(start + Duration::from_secs(60)),
        Err(VaultError::Locked)
    ));
    assert!(vault.locks_in(start).is_none());
}

#[test]
fn the_encoding_of_the_older_kinds_does_not_change() {
    let encoded: Vec<Vec<u8>> = SecretKind::ALL
        .iter()
        .map(|kind| postcard::to_allocvec(kind).unwrap())
        .collect();
    assert_eq!(encoded, [[0], [1], [2], [3], [4], [5]]);
}
