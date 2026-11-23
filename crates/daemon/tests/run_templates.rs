//! Run templates through the service, with the real sandbox when it is available.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use crownos_secretsd::service::RunStart;
use crownos_secretsd::{Caller, SecretsService};
use secrecy::SecretSlice;
use secrets_core::{
    Binding, Confirm, RunTemplate, SecretKind, SecretName, TemplateName, UseOutcome, VaultSettings,
};
use secrets_protocol::RunReply;
use secrets_protocol::transfer::TransferError;
use secrets_run::Launcher;
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

fn sandbox_available() -> bool {
    let launcher = Launcher::default();
    let available = launcher.bwrap.is_file() && launcher.systemd_run.is_file();
    if !available {
        eprintln!("bwrap or systemd-run is missing; skipping");
    }
    available
}

fn service(directory: &Path, launcher: Launcher, template: RunTemplate) -> SecretsService {
    let data_directory = directory.join("data");
    let vault = Vault::new(data_directory.join("secrets.vault")).with_kdf_params(KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    });
    let mut service =
        SecretsService::new(vault, vec![ADMIN.into()], data_directory).with_launcher(launcher);
    let now = Instant::now();
    let name = SecretName::parse("token").unwrap();
    service.init(&admin(), bytes(PASSWORD), now).unwrap();
    let mut settings = VaultSettings::default();
    settings.rate_limit.uses_per_minute = 1000;
    service
        .configure(&admin(), settings, bytes(PASSWORD), now)
        .unwrap();
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

fn show_token(cwd_glob: &str) -> RunTemplate {
    RunTemplate {
        command: vec![
            "/usr/bin/sh".into(),
            "-c".into(),
            r#"echo "token=$TOKEN"; printf %s "$TOKEN" | base64; printf %s "$TOKEN" | od -An -tx1 | tr -d ' \n'"#.into(),
        ],
        environment: [("TOKEN".to_owned(), SecretName::parse("token").unwrap())].into(),
        cwd_glob: cwd_glob.to_owned(),
        argument_patterns: vec!["[a-z]+".into()],
        timeout_seconds: 10,
        ..RunTemplate::default()
    }
}

async fn run(
    service: &mut SecretsService,
    caller: &Caller,
    arguments: &[&str],
    cwd: &str,
) -> RunReply {
    let arguments: Vec<String> = arguments.iter().map(|part| (*part).to_owned()).collect();
    match service
        .prepare_run(
            caller,
            &template_name("show"),
            &arguments,
            cwd,
            Instant::now(),
        )
        .unwrap()
    {
        RunStart::Refused(reply) => reply,
        RunStart::Ready(job) => job.execute().await.unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_template_runs_with_scrubbed_output() {
    if !sandbox_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let mut service = service(directory.path(), Launcher::default(), show_token(""));
    let reply = run(&mut service, &agent(), &["word"], "").await;
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
    let canonical = directory.path().canonicalize().unwrap();
    let glob = format!("{}/*", canonical.display());
    let missing = Launcher {
        bwrap: PathBuf::from("/nonexistent/bwrap"),
        ..Launcher::default()
    };
    let mut service = service(directory.path(), missing, show_token(&glob));

    let stranger = Caller::from_executable(Path::new("/usr/bin/other"));
    assert_eq!(
        run(&mut service, &stranger, &[], "").await,
        RunReply::Refused(UseOutcome::Denied)
    );
    for arguments in [
        &["--output=/tmp/x"][..],
        &["UPPER"],
        &["one", "two"],
        &["a b"],
    ] {
        let refused = run(&mut service, &agent(), arguments, allowed.to_str().unwrap()).await;
        assert_eq!(refused, RunReply::ArgumentsNotAllowed, "{arguments:?}");
    }

    let inside = allowed.join("project");
    std::fs::create_dir(&inside).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let escape = format!("{}/../../{}", inside.display(), outside.path().display());
    let link = allowed.join("link-out");
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    let data = canonical.join("data");
    for cwd in [
        outside.path().to_str().unwrap(),
        escape.as_str(),
        link.to_str().unwrap(),
        data.to_str().unwrap(),
        "relative/path",
        "",
    ] {
        let refused = run(&mut service, &agent(), &[], cwd).await;
        assert_eq!(refused, RunReply::CwdNotAllowed, "{cwd}");
    }
    let missing_sandbox = run(&mut service, &agent(), &["word"], inside.to_str().unwrap()).await;
    assert_eq!(missing_sandbox, RunReply::SandboxMissing);

    service.lock(&admin()).unwrap();
    assert_eq!(
        run(&mut service, &agent(), &[], "").await,
        RunReply::Refused(UseOutcome::Locked)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_default_binding_needs_a_confirmation_for_a_run() {
    let directory = tempfile::tempdir().unwrap();
    let mut service = service(directory.path(), Launcher::default(), show_token(""));
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
    let refused = run(&mut service, &agent(), &[], "").await;
    assert_eq!(refused, RunReply::Refused(UseOutcome::NeedsConfirmation));
}
