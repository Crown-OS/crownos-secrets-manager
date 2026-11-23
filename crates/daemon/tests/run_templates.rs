//! Run templates through the service, with the real bubblewrap when it is installed.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use crownos_secretsd::{Caller, SecretsService};
use secrecy::SecretSlice;
use secrets_core::{
    Binding, Confirm, RunTemplate, SecretKind, SecretName, TemplateName, UseOutcome,
};
use secrets_protocol::RunReply;
use secrets_protocol::transfer::TransferError;
use secrets_vault::{KdfParams, Vault};

const AGENT: &str = "/usr/bin/crownos-secrets-mcp";
const ADMIN: &str = "/usr/bin/crownos-secrets";
const PASSWORD: &[u8] = b"master";
const VALUE: &str = "tok_PLANTED_run_0123456789abcdef";

fn bytes(value: &'static [u8]) -> impl FnOnce() -> Result<SecretSlice<u8>, TransferError> {
    move || Ok(SecretSlice::from(value.to_vec()))
}

fn admin() -> Caller {
    Caller::from_executable(Path::new(ADMIN))
}

fn agent() -> Caller {
    Caller::from_executable(Path::new(AGENT))
}

fn template_name(text: &str) -> TemplateName {
    TemplateName::parse(text).unwrap()
}

fn service(directory: &Path, bwrap: PathBuf, cwd_glob: &str) -> SecretsService {
    let vault = Vault::new(directory.join("secrets.vault")).with_kdf_params(KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    });
    let mut service =
        SecretsService::new(vault, vec![ADMIN.into()], directory.to_owned()).with_bwrap(bwrap);
    let now = Instant::now();
    let name = SecretName::parse("token").unwrap();
    service.init(&admin(), bytes(PASSWORD), now).unwrap();
    service
        .add(
            &admin(),
            &name,
            SecretKind::Token,
            bytes(PASSWORD),
            bytes(VALUE.as_bytes()),
            now,
        )
        .unwrap();
    let binding = Binding {
        agents: vec![AGENT.into()],
        confirm: Some(Confirm::Never),
        ..Binding::default()
    };
    service
        .bind(&admin(), &name, binding, bytes(PASSWORD), now)
        .unwrap();
    let template = RunTemplate {
        command: vec![
            "/usr/bin/sh".into(),
            "-c".into(),
            r#"echo "token=$TOKEN"; printf %s "$TOKEN" | base64; printf %s "$TOKEN" | od -An -tx1 | tr -d ' \n'"#.into(),
        ],
        environment: [("TOKEN".to_owned(), name)].into(),
        cwd_glob: cwd_glob.to_owned(),
        timeout_seconds: 10,
        ..RunTemplate::default()
    };
    service
        .set_template(
            &admin(),
            &template_name("show"),
            Some(template),
            bytes(PASSWORD),
            now,
        )
        .unwrap();
    service
}

#[tokio::test(flavor = "multi_thread")]
async fn a_template_runs_with_scrubbed_output() {
    if !Path::new(secrets_run::BWRAP).is_file() {
        eprintln!("bwrap is not installed; skipping");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let mut service = service(directory.path(), secrets_run::BWRAP.into(), "");
    let reply = service
        .run(&agent(), &template_name("show"), &[], "", Instant::now())
        .unwrap();
    let RunReply::Finished(output) = reply else {
        panic!("{reply:?}");
    };
    assert_eq!(output.exit_code, Some(0), "{output:?}");
    assert!(output.stdout.contains("token=[secret:token]"), "{output:?}");
    let hex: String = VALUE.bytes().map(|byte| format!("{byte:02x}")).collect();
    assert!(
        !output.stdout.contains(VALUE) && !output.stdout.contains(&hex),
        "{output:?}"
    );
    assert!(!output.stdout.contains("dG9rX1BMQU5URUR"), "{output:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_come_before_the_sandbox() {
    let directory = tempfile::tempdir().unwrap();
    let allowed = directory.path().join("allowed");
    std::fs::create_dir(&allowed).unwrap();
    let glob = format!(
        "{}/*",
        directory
            .path()
            .canonicalize()
            .unwrap()
            .join("allowed")
            .display()
    );
    let mut service = service(directory.path(), "/nonexistent/bwrap".into(), &glob);
    let now = Instant::now();

    let unknown = service
        .run(&agent(), &template_name("missing"), &[], "", now)
        .unwrap();
    assert_eq!(unknown, RunReply::Refused(UseOutcome::Unknown));
    let stranger = Caller::from_executable(Path::new("/usr/bin/other"));
    let denied = service
        .run(&stranger, &template_name("show"), &[], "", now)
        .unwrap();
    assert_eq!(denied, RunReply::Refused(UseOutcome::Denied));
    let arguments = ["--extra".to_owned()];
    let extra = service
        .run(&agent(), &template_name("show"), &arguments, "", now)
        .unwrap();
    assert_eq!(extra, RunReply::ArgumentsNotAllowed);

    let inside = allowed.join("project");
    std::fs::create_dir(&inside).unwrap();
    let outside = directory.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let escape = format!("{}/../../outside", inside.display());
    for cwd in [
        outside.to_str().unwrap(),
        escape.as_str(),
        "relative/path",
        "",
    ] {
        let refused = service
            .run(&agent(), &template_name("show"), &[], cwd, now)
            .unwrap();
        assert_eq!(refused, RunReply::CwdNotAllowed, "{cwd}");
    }
    let missing_sandbox = service
        .run(
            &agent(),
            &template_name("show"),
            &[],
            inside.to_str().unwrap(),
            now,
        )
        .unwrap();
    assert_eq!(missing_sandbox, RunReply::SandboxMissing);

    service.lock(&admin()).unwrap();
    let locked = service
        .run(&agent(), &template_name("show"), &[], "", now)
        .unwrap();
    assert_eq!(locked, RunReply::Refused(UseOutcome::Locked));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_default_binding_needs_a_confirmation_for_a_run() {
    let directory = tempfile::tempdir().unwrap();
    let mut service = service(directory.path(), "/nonexistent/bwrap".into(), "");
    let now = Instant::now();
    let default_confirm = Binding {
        agents: vec![AGENT.into()],
        ..Binding::default()
    };
    service
        .bind(
            &admin(),
            &SecretName::parse("token").unwrap(),
            default_confirm,
            bytes(PASSWORD),
            now,
        )
        .unwrap();
    let refused = service
        .run(&agent(), &template_name("show"), &[], "", now)
        .unwrap();
    assert_eq!(refused, RunReply::Refused(UseOutcome::NeedsConfirmation));
}
