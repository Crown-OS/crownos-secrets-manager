//! Real bubblewrap runs. They are skipped when bwrap is not installed.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use base64::Engine as _;
use secrecy::SecretSlice;
use secrets_core::{RunTemplate, Scrubber, SecretName};
use secrets_run::{
    CheckedDirectory, Launcher, SandboxError, SandboxOutput, SandboxRequest, run_in_sandbox,
};

const VALUE: &str = "ghp_PLANTED_run_value_0123456789";

/// A private user manager that the test run set up; see `TEST_USER_RUNTIME_VARIABLE`.
fn test_launcher() -> Option<Launcher> {
    let launcher = Launcher::private_test_manager();
    if launcher.is_none() {
        eprintln!("no private user manager; skipping");
    }
    launcher
}

fn shell_template(script: &str) -> RunTemplate {
    RunTemplate {
        command: vec!["/usr/bin/sh".into(), "-c".into(), script.into()],
        environment: [("SECRET".to_owned(), SecretName::parse("planted").unwrap())].into(),
        timeout_seconds: 10,
        ..RunTemplate::default()
    }
}

async fn run(
    launcher: &Launcher,
    template: &RunTemplate,
    cwd: Option<&CheckedDirectory>,
) -> Result<SandboxOutput, SandboxError> {
    let mut scrubber = Scrubber::new();
    scrubber.add_secret(&SecretName::parse("planted").unwrap(), VALUE.as_bytes());
    run_in_sandbox(SandboxRequest {
        launcher,
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
    let Some(launcher) = test_launcher() else {
        return;
    };
    let script = r#"echo "plain $SECRET"; printf %s "$SECRET" | base64; printf %s "$SECRET" | od -An -tx1 | tr -d ' \n'; echo; echo "err $SECRET" >&2"#;
    let output = run(&launcher, &shell_template(script), None).await.unwrap();
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
    let Some(launcher) = test_launcher() else {
        return;
    };
    let output = run(
        &launcher,
        &shell_template("tr '\\0' ' ' < /proc/1/cmdline"),
        None,
    )
    .await
    .unwrap();
    let stdout = text(&output.stdout);
    assert!(stdout.contains("--args"), "{stdout}");
    assert!(!stdout.contains("[secret:"), "{stdout}");
}

#[tokio::test]
async fn there_is_no_network_and_the_cwd_is_read_only() {
    let Some(launcher) = test_launcher() else {
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let checked = CheckedDirectory::check(directory.path()).unwrap();
    let cwd = checked.path().to_owned();
    let script = r#"for interface in $(tail -n +3 /proc/net/dev | cut -d: -f1); do echo "interface:$interface"; done
for descriptor in /proc/self/fd/*; do echo "fd:$(readlink "$descriptor")"; done
echo "stdin-bytes:$(wc -c < /dev/stdin 2>/dev/null)"
pwd
touch written 2>/dev/null && echo wrote || echo read-only"#;
    let output = run(&launcher, &shell_template(script), Some(&checked))
        .await
        .unwrap();
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
    let Some(launcher) = test_launcher() else {
        return;
    };
    let mut slow = shell_template("sleep 30");
    slow.timeout_seconds = 1;
    let output = run(&launcher, &slow, None).await.unwrap();
    assert!(output.timed_out);
    assert_eq!(output.exit_code, None);

    let mut loud = shell_template("yes");
    loud.max_output_bytes = 10_000;
    let output = run(&launcher, &loud, None).await.unwrap();
    assert!(output.truncated);
}

#[tokio::test]
async fn a_missing_bwrap_is_reported() {
    let template = shell_template("true");
    let launcher = Launcher {
        bwrap: "/nonexistent/bwrap".into(),
        ..Launcher::default()
    };
    let result = run_in_sandbox(SandboxRequest {
        launcher: &launcher,
        template: &template,
        arguments: &[],
        cwd: None,
        environment: Vec::new(),
        scrubber: Arc::new(Scrubber::new()),
    })
    .await;
    assert!(matches!(result, Err(SandboxError::SandboxMissing)));
}

#[tokio::test]
async fn a_command_over_its_memory_limit_is_stopped() {
    let Some(launcher) = test_launcher() else {
        return;
    };
    let mut hungry =
        shell_template("big=$(head -c 200000000 /dev/zero | tr '\\0' a); echo ${#big}");
    hungry.memory_max_megabytes = 32;
    hungry.timeout_seconds = 30;
    let output = run(&launcher, &hungry, None).await.unwrap();
    assert_ne!(output.exit_code, Some(0), "{output:?}");
    assert!(!text(&output.stdout).contains("200000000"), "{output:?}");
}

#[tokio::test]
async fn a_directory_swapped_after_the_check_stops_the_run() {
    let Some(launcher) = test_launcher() else {
        return;
    };
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let swapped = CheckedDirectory::check(first.path())
        .unwrap()
        .with_identity_of(&CheckedDirectory::check(second.path()).unwrap());
    let output = run(&launcher, &shell_template("echo ran"), Some(&swapped))
        .await
        .unwrap();
    assert!(output.cwd_changed, "{output:?}");
    assert!(!text(&output.stdout).contains("ran"));
    let forged = run(&launcher, &shell_template("echo ran; exit 125"), None)
        .await
        .unwrap();
    assert!(!forged.cwd_changed, "an exit code faked the report");
}

#[tokio::test]
async fn no_value_reaches_the_journal() {
    let Some(launcher) = test_launcher() else {
        return;
    };
    let output = run(&launcher, &shell_template(r#"echo "$SECRET""#), None)
        .await
        .unwrap();
    assert_eq!(output.exit_code, Some(0), "{output:?}");
    let journal = std::process::Command::new("journalctl")
        .args(["--user", "--since=-5min", "--output=cat", "--no-pager"])
        .output()
        .unwrap();
    assert!(!text(&journal.stdout).contains(VALUE));
}
