//! The checks of the service, with a controlled clock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::time::{Duration, Instant};

use crownos_secretsd::{Caller, SecretsService, ServiceError};
use secrecy::SecretSlice;
use secrets_core::{
    Binding, RunTemplate, SecretKind, SecretName, TemplateName, UseOutcome, VaultSettings,
};
use secrets_protocol::transfer::TransferError;
use secrets_vault::{KdfParams, Vault};

const AGENT: &str = "/usr/bin/crownos-secrets-mcp";
const ADMIN: &str = "/usr/bin/crownos-secrets";
const PASSWORD: &[u8] = b"master";

fn name(text: &str) -> SecretName {
    SecretName::parse(text).unwrap()
}

fn bytes(value: &'static [u8]) -> impl FnOnce() -> Result<SecretSlice<u8>, TransferError> {
    move || Ok(SecretSlice::from(value.to_vec()))
}

fn admin() -> Caller {
    Caller::from_executable(Path::new(ADMIN))
}

fn agent() -> Caller {
    Caller::from_executable(Path::new(AGENT))
}

/// An unlocked vault with the secret `bound`, which `AGENT` may use.
fn service(vault_path: &Path, now: Instant, settings: VaultSettings) -> SecretsService {
    let vault = Vault::new(vault_path.to_owned()).with_kdf_params(KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    });
    let mut service =
        SecretsService::new(vault, vec![ADMIN.into()], vault_path.with_extension("data"));
    service.init(&admin(), bytes(PASSWORD), now).unwrap();
    service
        .configure(&admin(), settings, bytes(PASSWORD), now)
        .unwrap();
    service
        .add(
            &admin(),
            &name("bound"),
            SecretKind::Token,
            bytes(PASSWORD),
            bytes(b"value"),
            now,
        )
        .unwrap();
    let binding = Binding {
        agents: vec![AGENT.into()],
        ..Binding::default()
    };
    service
        .bind(&admin(), &name("bound"), binding, bytes(PASSWORD), now)
        .unwrap();
    service
}

#[test]
fn uses_per_minute_from_the_sealed_settings_limit_each_caller() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut settings = VaultSettings::default();
    settings.rate_limit.uses_per_minute = 2;
    let mut service = service(&directory.path().join("v"), now, settings);
    for _ in 0..2 {
        let passed = service.use_secrets(&agent(), &[name("bound")], "window:1", now);
        assert!(matches!(passed, Err(ServiceError::Unavailable)));
    }
    let limited = service.use_secrets(&agent(), &[name("bound")], "window:1", now);
    assert_eq!(limited.unwrap(), UseOutcome::RateLimited);
    let quiet = service.use_secrets(&agent(), &[name("bound")], "window:1", now);
    assert_eq!(quiet.unwrap(), UseOutcome::RateLimited);
    assert_eq!(service.take_events().len(), 1);
    let later = now + Duration::from_secs(30);
    let refilled = service.use_secrets(&agent(), &[name("bound")], "window:1", later);
    assert!(matches!(refilled, Err(ServiceError::Unavailable)));
}

#[test]
fn requests_are_limited_and_each_caller_sees_only_its_own() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut settings = VaultSettings::default();
    settings.rate_limit.requests_per_hour = 100;
    let mut service = service(&directory.path().join("v"), now, settings);
    for index in 0..4 {
        let request = service.request(
            &agent(),
            name(&format!("needed{index}")),
            SecretKind::ApiKey,
            "search",
            now,
        );
        assert!(request.is_ok());
    }
    let full = service.request(
        &agent(),
        name("one-more"),
        SecretKind::ApiKey,
        "search",
        now,
    );
    assert!(matches!(full, Err(ServiceError::TooManyRequests)));
    let other = Caller::from_executable(Path::new("/usr/bin/other-agent"));
    assert!(
        service
            .request(&other, name("theirs"), SecretKind::Token, "x", now)
            .is_ok()
    );
    assert_eq!(service.status(&other, now).pending_requests.len(), 1);
    assert_eq!(service.status(&agent(), now).pending_requests.len(), 4);
    assert_eq!(service.status(&admin(), now).pending_requests.len(), 5);
}

#[test]
fn requests_per_hour_limit_requests() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut settings = VaultSettings::default();
    settings.rate_limit.requests_per_hour = 1;
    let mut service = service(&directory.path().join("v"), now, settings);
    assert!(
        service
            .request(&agent(), name("needed"), SecretKind::ApiKey, "a", now)
            .is_ok()
    );
    let limited = service.request(&agent(), name("needed"), SecretKind::ApiKey, "a", now);
    assert!(matches!(limited, Err(ServiceError::RateLimited)));
}

#[test]
fn templates_need_the_password_and_are_listed_only_while_unlocked() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut service = service(&directory.path().join("v"), now, VaultSettings::default());
    let template = RunTemplate {
        command: vec!["true".into()],
        environment: [("TOKEN".to_owned(), name("bound"))].into(),
        ..RunTemplate::default()
    };
    let template_name = TemplateName::parse("check").unwrap();
    let wrong = service.set_template(
        &admin(),
        &template_name,
        Some(template.clone()),
        bytes(b"wrong"),
        now,
    );
    assert!(matches!(wrong, Err(ServiceError::Vault(_))));
    service
        .set_template(
            &admin(),
            &template_name,
            Some(template),
            bytes(PASSWORD),
            now,
        )
        .unwrap();
    assert_eq!(service.templates(now).unwrap().len(), 1);
    service.lock(&admin()).unwrap();
    assert!(matches!(service.templates(now), Err(ServiceError::Locked)));
}

#[test]
fn the_vault_locks_after_the_sealed_minutes() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let settings = VaultSettings {
        lock_after_minutes: 1,
        ..VaultSettings::default()
    };
    let mut service = service(&directory.path().join("v"), now, settings);
    service.lock(&admin()).unwrap();
    service.unlock(&admin(), bytes(PASSWORD), now).unwrap();
    assert!(
        !service
            .status(&agent(), now + Duration::from_secs(59))
            .locked
    );
    assert!(
        service
            .status(&agent(), now + Duration::from_secs(61))
            .locked
    );
    let late = now + Duration::from_secs(61);
    let locked = service.use_secrets(&agent(), &[name("bound")], "window:1", late);
    assert_eq!(locked.unwrap(), UseOutcome::Locked);
}

#[test]
fn a_non_admin_never_makes_the_daemon_read_its_pipes() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut service = service(&directory.path().join("v"), now, VaultSettings::default());
    let refused = service.unlock(&agent(), || panic!("the pipe was read"), now);
    assert!(matches!(refused, Err(ServiceError::NotAdmin)));
    let refused = service.add(
        &agent(),
        &name("x"),
        SecretKind::Token,
        || panic!("the password pipe was read"),
        || panic!("the value pipe was read"),
        now,
    );
    assert!(matches!(refused, Err(ServiceError::NotAdmin)));
}

#[test]
fn a_wrong_password_reads_no_value() {
    let directory = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut service = service(&directory.path().join("v"), now, VaultSettings::default());
    let refused = service.add(
        &admin(),
        &name("x"),
        SecretKind::Token,
        bytes(b"wrong"),
        || panic!("the value pipe was read"),
        now,
    );
    assert!(matches!(refused, Err(ServiceError::Vault(_))));
}
