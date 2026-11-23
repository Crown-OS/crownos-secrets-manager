//! The checks of the service, with a controlled clock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::time::{Duration, Instant};

use crownos_secretsd::{Caller, MemoryConfigStore, SecretsService, ServiceError};
use secrecy::SecretSlice;
use secrets_core::config::{RunTemplate, SecretEntry};
use secrets_core::{Binding, SecretKind, SecretName, SecretsConfig, UseOutcome};
use secrets_protocol::transfer::TransferError;
use secrets_vault::{KdfParams, Vault};

const AGENT: &str = "/usr/bin/crownos-secrets-mcp";
const ADMIN: &str = "/usr/bin/crownos-secrets";

fn name(text: &str) -> SecretName {
    SecretName::parse(text).unwrap()
}

fn bytes(value: &'static [u8]) -> impl FnOnce() -> Result<SecretSlice<u8>, TransferError> {
    move || Ok(SecretSlice::from(value.to_vec()))
}

fn service(
    vault_path: &Path,
    edit: impl FnOnce(&mut SecretsConfig),
) -> SecretsService<MemoryConfigStore> {
    let mut config = SecretsConfig {
        admin_executables: vec![ADMIN.into()],
        ..SecretsConfig::default()
    };
    config.secrets.insert(
        name("bound"),
        SecretEntry {
            kind: SecretKind::Token,
            binding: Binding {
                agents: vec![AGENT.into()],
                ..Binding::default()
            },
        },
    );
    edit(&mut config);
    let vault = Vault::new(vault_path.to_owned(), Duration::ZERO).with_kdf_params(KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    });
    SecretsService::new(MemoryConfigStore::new(config), vault)
}

fn unlocked_with_bound_secret(
    vault_path: &Path,
    now: Instant,
    edit: impl FnOnce(&mut SecretsConfig),
) -> SecretsService<MemoryConfigStore> {
    let admin = Caller::from_executable(Path::new(ADMIN));
    let mut service = service(vault_path, edit);
    service.unlock(&admin, bytes(b"master"), now).unwrap();
    service
        .add(
            &admin,
            &name("bound"),
            SecretKind::Token,
            bytes(b"value"),
            now,
        )
        .unwrap();
    service
}

#[test]
fn uses_per_minute_from_the_config_limit_each_caller() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut service = unlocked_with_bound_secret(&directory.path().join("v"), now, |config| {
        config.rate_limit.uses_per_minute = 2;
    });
    let agent = Caller::from_executable(Path::new(AGENT));
    for _ in 0..2 {
        let passed = service.use_secrets(&agent, &[name("bound")], "window:1", now);
        assert!(matches!(passed, Err(ServiceError::Unavailable)));
    }
    let limited = service.use_secrets(&agent, &[name("bound")], "window:1", now);
    assert_eq!(limited.unwrap(), UseOutcome::RateLimited);
    let later = now + Duration::from_secs(30);
    let refilled = service.use_secrets(&agent, &[name("bound")], "window:1", later);
    assert!(matches!(refilled, Err(ServiceError::Unavailable)));
}

#[test]
fn requests_per_hour_limit_requests() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut service = service(&directory.path().join("v"), |config| {
        config.rate_limit.requests_per_hour = 1;
    });
    let agent = Caller::from_executable(Path::new(AGENT));
    let first = service.request(&agent, name("needed"), SecretKind::ApiKey, "search", now);
    assert!(first.is_ok());
    let second = service.request(&agent, name("needed"), SecretKind::ApiKey, "search", now);
    assert!(matches!(second, Err(ServiceError::RateLimited)));
    assert_eq!(service.status(now).pending_requests.len(), 1);
}

#[test]
fn run_templates_check_every_secret_in_their_environment() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut service = unlocked_with_bound_secret(&directory.path().join("v"), now, |config| {
        let template = |secret: &str| RunTemplate {
            command: vec!["true".into()],
            environment: [("TOKEN".to_owned(), name(secret))].into(),
            network: Vec::new(),
        };
        config
            .run_templates
            .insert("bound-only".into(), template("bound"));
        config
            .run_templates
            .insert("unbound".into(), template("not-stored"));
    });
    let agent = Caller::from_executable(Path::new(AGENT));
    let unknown_template = service.run_template(&agent, "missing", now);
    assert_eq!(unknown_template.unwrap(), UseOutcome::Unknown);
    let unknown_secret = service.run_template(&agent, "unbound", now);
    assert_eq!(unknown_secret.unwrap(), UseOutcome::Unknown);
    let passed = service.run_template(&agent, "bound-only", now);
    assert!(matches!(passed, Err(ServiceError::Unavailable)));
    let stranger = Caller::from_executable(Path::new("/usr/bin/other"));
    let denied = service.run_template(&stranger, "bound-only", now);
    assert_eq!(denied.unwrap(), UseOutcome::Denied);
}

#[test]
fn the_vault_locks_after_the_configured_minutes() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut service = unlocked_with_bound_secret(&directory.path().join("v"), now, |config| {
        config.unlock.lock_after_minutes = 1;
    });
    assert!(!service.status(now + Duration::from_secs(59)).locked);
    assert!(service.status(now + Duration::from_secs(61)).locked);
    let agent = Caller::from_executable(Path::new(AGENT));
    let locked = service.use_secrets(
        &agent,
        &[name("bound")],
        "window:1",
        now + Duration::from_secs(61),
    );
    assert_eq!(locked.unwrap(), UseOutcome::Locked);
}

#[test]
fn a_non_admin_never_makes_the_daemon_read_its_pipe() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut service = service(&directory.path().join("v"), |_| {});
    let agent = Caller::from_executable(Path::new(AGENT));
    let refused = service.unlock(&agent, || panic!("the pipe was read"), now);
    assert!(matches!(refused, Err(ServiceError::NotAdmin)));
    let refused = service.add(
        &agent,
        &name("x"),
        SecretKind::Token,
        || panic!("read"),
        now,
    );
    assert!(matches!(refused, Err(ServiceError::NotAdmin)));
}
