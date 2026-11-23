//! The consent dialog runs as a process: its exit and its last line are the answer.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use crownos_secretsd::confirmation::{
    ConfirmationAsker, DialogProcessAsker, DialogRequest, Verdict,
};
use secrets_core::SecretName;
use secrets_run::Launcher;

fn request() -> DialogRequest {
    DialogRequest {
        app_key: "exe:/usr/bin/agent".into(),
        agent: "agent".into(),
        names: vec![SecretName::parse("api").unwrap()],
        target: "proxy to api.example.com".into(),
        session_minutes: None,
    }
}

fn script(directory: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The dialog runs as a transient service of a private user manager. Skipped without one.
#[tokio::test]
async fn the_answer_comes_from_the_dialog_service() {
    let Some(launcher) = Launcher::private_test_manager() else {
        eprintln!("no private user manager; skipping");
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let allow = script(directory.path(), "allow", "echo grant");
    let deny = script(directory.path(), "deny", "exit 1");
    let wrong_word = script(directory.path(), "wrong", "echo yes");
    let limits = script(
        directory.path(),
        "limits",
        "cgroup=$(cut -d: -f3 /proc/self/cgroup)\n\
         [ \"$(cat /sys/fs/cgroup$cgroup/memory.max)\" = 1073741824 ] && echo grant",
    );
    for (dialog, expected) in [
        (allow, Verdict::Granted),
        (deny, Verdict::Denied),
        (wrong_word, Verdict::Denied),
        (limits, Verdict::Granted),
        (directory.path().join("missing"), Verdict::Unreachable),
    ] {
        let verdict = DialogProcessAsker::trusting(dialog.clone(), launcher.clone())
            .ask(request())
            .await;
        assert_eq!(verdict, expected, "{}", dialog.display());
    }
}
