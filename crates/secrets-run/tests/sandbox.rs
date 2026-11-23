//! Real bubblewrap runs. They are skipped when bwrap is not installed.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use secrecy::SecretSlice;
use secrets_core::{RunTemplate, Scrubber, SecretName};
use secrets_run::{BWRAP, SandboxError, SandboxOutput, SandboxRequest, run_in_sandbox};

const VALUE: &str = "ghp_PLANTED_run_value_0123456789";

fn bwrap_installed() -> bool {
    let installed = Path::new(BWRAP).is_file();
    if !installed {
        eprintln!("bwrap is not installed; skipping");
    }
    installed
}

fn shell_template(script: &str) -> RunTemplate {
    RunTemplate {
        command: vec!["/usr/bin/sh".into(), "-c".into(), script.into()],
        environment: [("SECRET".to_owned(), SecretName::parse("planted").unwrap())].into(),
        timeout_seconds: 10,
        ..RunTemplate::default()
    }
}

async fn run(template: &RunTemplate, cwd: Option<&Path>) -> Result<SandboxOutput, SandboxError> {
    let mut scrubber = Scrubber::new();
    scrubber.add_secret(&SecretName::parse("planted").unwrap(), VALUE.as_bytes());
    run_in_sandbox(SandboxRequest {
        bwrap: Path::new(BWRAP),
        template,
        arguments: &[],
        cwd,
        environment: vec![(
            "SECRET".into(),
            SecretSlice::from(VALUE.as_bytes().to_vec()),
        )],
        scrubber: Arc::new(scrubber),
    })
    .await
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn the_value_and_its_encodings_never_come_out() {
    if !bwrap_installed() {
        return;
    }
    let script = r#"echo "plain $SECRET"; printf %s "$SECRET" | base64; printf %s "$SECRET" | od -An -tx1 | tr -d ' \n'; echo; echo "err $SECRET" >&2"#;
    let output = run(&shell_template(script), None).await.unwrap();
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.exit_code, Some(0), "{stdout} {stderr}");
    let base64 = base64::engine::general_purpose::STANDARD.encode(VALUE);
    let hex: String = VALUE.bytes().map(|byte| format!("{byte:02x}")).collect();
    for form in [VALUE, base64.as_str(), hex.as_str()] {
        assert!(!stdout.contains(form), "{stdout}");
        assert!(!stderr.contains(form), "{stderr}");
    }
    assert!(stdout.contains("plain [secret:planted]"), "{stdout}");
    assert!(stderr.contains("err [secret:planted]"), "{stderr}");
}

#[tokio::test]
async fn the_value_is_not_in_the_command_line_of_bwrap() {
    if !bwrap_installed() {
        return;
    }
    let output = run(&shell_template("tr '\\0' ' ' < /proc/1/cmdline"), None)
        .await
        .unwrap();
    let stdout = text(&output.stdout);
    assert!(stdout.contains("--args"), "{stdout}");
    assert!(!stdout.contains("[secret:"), "{stdout}");
}

#[tokio::test]
async fn there_is_no_network_and_the_cwd_is_read_only() {
    if !bwrap_installed() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path().canonicalize().unwrap();
    let script = r#"for interface in $(tail -n +3 /proc/net/dev | cut -d: -f1); do echo "interface:$interface"; done
for descriptor in /proc/self/fd/*; do echo "fd:$(readlink "$descriptor")"; done
echo "stdin-bytes:$(wc -c < /dev/stdin 2>/dev/null)"
pwd
touch written 2>/dev/null && echo wrote || echo read-only"#;
    let output = run(&shell_template(script), Some(&cwd)).await.unwrap();
    let stdout = text(&output.stdout);
    let interfaces: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("interface:"))
        .map(str::trim)
        .collect();
    assert_eq!(interfaces, ["interface:lo"], "{stdout}");
    let pipes = stdout
        .lines()
        .filter(|line| line.starts_with("fd:pipe:"))
        .count();
    assert!(!stdout.contains("memfd"), "{stdout}");
    assert_eq!(
        pipes, 2,
        "stdout and stderr only, no pipe of another run: {stdout}"
    );
    assert!(stdout.contains("fd:/dev/null"), "{stdout}");
    assert!(stdout.contains("stdin-bytes:0"), "{stdout}");
    assert!(stdout.contains(&*cwd.to_string_lossy()), "{stdout}");
    assert!(stdout.contains("read-only"), "{stdout}");
}

#[tokio::test]
async fn time_and_output_limits_stop_the_command() {
    if !bwrap_installed() {
        return;
    }
    let mut slow = shell_template("sleep 30");
    slow.timeout_seconds = 1;
    let output = run(&slow, None).await.unwrap();
    assert!(output.timed_out);
    assert_eq!(output.exit_code, None);

    let mut loud = shell_template("yes");
    loud.max_output_bytes = 10_000;
    let output = run(&loud, None).await.unwrap();
    assert!(output.truncated);
}

#[tokio::test]
async fn a_missing_bwrap_is_reported() {
    let template = shell_template("true");
    let result = run_in_sandbox(SandboxRequest {
        bwrap: Path::new("/nonexistent/bwrap"),
        template: &template,
        arguments: &[],
        cwd: None,
        environment: Vec::new(),
        scrubber: Arc::new(Scrubber::new()),
    })
    .await;
    assert!(matches!(result, Err(SandboxError::SandboxMissing)));
}
