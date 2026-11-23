//! The question through the root-owned `crownos-portal-dialog`. It runs in a transient user
//! service (`systemd-run --user --pipe --wait --collect`) with limits of its own, not as a child
//! that inherits the daemon's strict ones. The daemon owns the pipe the answer comes back on;
//! the compositor keeps synthetic input away from that executable's dialog.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

use crownos_config::schema::AppKey;
use secrets_run::Launcher;
use tokio::process::Command;

use super::{ANSWER_TIME, ConfirmationAsker, DialogRequest, Verdict, VerdictFuture};

/// Where xdg-desktop-portal-crownos installs the dialog.
const INSTALLED_DIALOG: &str = "/usr/lib/crownos-portal-dialog";
/// A development build of the dialog, honoured in a debug build only.
#[cfg(debug_assertions)]
const DIALOG_OVERRIDE_VARIABLE: &str = "CROWN_CONSENT_DIALOG";
/// The id of the Allow button, which the dialog prints when it is pressed.
const GRANT: &str = "grant";

/// The dialog's own limits. It draws with the GPU, so it gets no `MemoryDenyWriteExecute`.
const DIALOG_PROPERTIES: [&str; 4] = [
    "MemoryMax=1G",
    "NoNewPrivileges=yes",
    "RuntimeMaxSec=130",
    "CollectMode=inactive-or-failed",
];

#[derive(Debug, Clone)]
pub struct DialogProcessAsker {
    executable: PathBuf,
    must_be_root_owned: bool,
    launcher: Launcher,
}

impl DialogProcessAsker {
    pub fn installed() -> Self {
        #[cfg(debug_assertions)]
        if let Some(path) = std::env::var_os(DIALOG_OVERRIDE_VARIABLE) {
            return Self {
                executable: PathBuf::from(path),
                must_be_root_owned: false,
                launcher: Launcher::default(),
            };
        }
        Self {
            executable: PathBuf::from(INSTALLED_DIALOG),
            must_be_root_owned: true,
            launcher: Launcher::default(),
        }
    }

    /// This dialog through this user manager, without the root-owned check: for tests and tools.
    pub const fn trusting(executable: PathBuf, launcher: Launcher) -> Self {
        Self {
            executable,
            must_be_root_owned: false,
            launcher,
        }
    }

    fn is_trusted(&self) -> bool {
        self.executable.is_file()
            && (!self.must_be_root_owned
                || !AppKey::HostExecutable {
                    path: self.executable.clone(),
                }
                .is_session_only(None))
    }
}

impl ConfirmationAsker for DialogProcessAsker {
    fn ask(&self, request: DialogRequest) -> VerdictFuture {
        let trusted = self.is_trusted();
        let asker = self.clone();
        Box::pin(async move {
            if !trusted {
                tracing::warn!(dialog = %asker.executable.display(), "the consent dialog is not installed");
                return Verdict::Unreachable;
            }
            asker.ask_in_service(&request).await
        })
    }
}

impl DialogProcessAsker {
    /// Runs the dialog in a transient service and waits up to [`ANSWER_TIME`]; the service is
    /// stopped when no answer came.
    async fn ask_in_service(&self, request: &DialogRequest) -> Verdict {
        static NEXT_DIALOG: AtomicU64 = AtomicU64::new(1);
        let unit = format!(
            "crownos-secrets-dialog-{}-{}",
            std::process::id(),
            NEXT_DIALOG.fetch_add(1, Ordering::Relaxed)
        );
        let mut command = Command::new(&self.launcher.systemd_run);
        command
            .env_clear()
            .envs(self.launcher.user_manager_environment())
            .args(["--user", "--pipe", "--wait", "--collect", "--quiet"])
            .arg(format!("--unit={unit}"));
        for property in DIALOG_PROPERTIES {
            command.arg("--property").arg(property);
        }
        if let Some(display) = std::env::var_os("WAYLAND_DISPLAY") {
            let mut setting = std::ffi::OsString::from("--setenv=WAYLAND_DISPLAY=");
            setting.push(display);
            command.arg(setting);
        }
        command
            .arg("--")
            .arg(&self.executable)
            .args(dialog_arguments(request))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                tracing::warn!(%error, "cannot start the consent dialog");
                return Verdict::Unreachable;
            }
        };
        match tokio::time::timeout(ANSWER_TIME, child.wait_with_output()).await {
            Ok(Ok(output))
                if output.status.success() && last_line(&output.stdout) == Some(GRANT) =>
            {
                Verdict::Granted
            }
            Ok(Ok(_)) => Verdict::Denied,
            Err(_) => {
                self.stop(&unit).await;
                Verdict::Denied
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, "the consent dialog failed");
                Verdict::Unreachable
            }
        }
    }

    async fn stop(&self, unit: &str) {
        let stopped = Command::new(&self.launcher.systemctl)
            .env_clear()
            .envs(self.launcher.user_manager_environment())
            .args(["--user", "stop", unit])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        if let Err(error) = stopped {
            tracing::warn!(%error, "cannot stop an unanswered consent dialog");
        }
    }
}

fn dialog_arguments(request: &DialogRequest) -> Vec<String> {
    vec![
        "--icon".into(),
        "warning".into(),
        "--title".into(),
        request.title(),
        "--message".into(),
        request.body(),
        "--cancel".into(),
        "Deny".into(),
        "--choice".into(),
        format!("{GRANT}=Allow"),
    ]
}

fn last_line(output: &[u8]) -> Option<&str> {
    std::str::from_utf8(output)
        .ok()?
        .lines()
        .last()
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_last_line_is_the_answer() {
        assert_eq!(last_line(b"warning\ngrant\n"), Some("grant"));
        assert_eq!(last_line(b""), None);
        assert_eq!(last_line(&[0xff]), None);
    }

    #[test]
    fn a_dialog_that_the_user_can_change_is_not_trusted() {
        let asker = DialogProcessAsker {
            executable: std::env::current_exe().unwrap_or_default(),
            must_be_root_owned: true,
            launcher: Launcher::default(),
        };
        assert!(!asker.is_trusted());
    }
}
