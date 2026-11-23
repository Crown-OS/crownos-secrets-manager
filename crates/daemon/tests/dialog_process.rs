//! The consent dialog runs as a process: its exit and its last line are the answer.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use crownos_secretsd::confirmation::{
    ConfirmationAsker, DialogProcessAsker, DialogRequest, Verdict,
};
use secrets_core::SecretName;

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

#[tokio::test]
async fn the_answer_comes_from_the_dialog_process() {
    let directory = tempfile::tempdir().unwrap();
    let allow = script(directory.path(), "allow", "echo grant");
    let deny = script(directory.path(), "deny", "exit 1");
    let wrong_word = script(directory.path(), "wrong", "echo yes");
    for (dialog, expected) in [
        (allow, Verdict::Granted),
        (deny, Verdict::Denied),
        (wrong_word, Verdict::Denied),
        (directory.path().join("missing"), Verdict::Unreachable),
    ] {
        let verdict = DialogProcessAsker::trusting(dialog.clone())
            .ask(request())
            .await;
        assert_eq!(verdict, expected, "{}", dialog.display());
    }
}
