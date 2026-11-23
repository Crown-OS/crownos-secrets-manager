//! The question through the root-owned `crownos-portal-dialog`, started directly. The
//! compositor keeps synthetic input away from that executable's dialog, and no D-Bus service is
//! in the path.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use crownos_config::schema::AppKey;
use tokio::process::Command;

use super::{ANSWER_TIME, ConfirmationAsker, DialogRequest, Verdict, VerdictFuture};

/// Where xdg-desktop-portal-crownos installs the dialog.
const INSTALLED_DIALOG: &str = "/usr/lib/crownos-portal-dialog";
/// A development build of the dialog, honoured in a debug build only.
#[cfg(debug_assertions)]
const DIALOG_OVERRIDE_VARIABLE: &str = "CROWN_CONSENT_DIALOG";
/// The id of the Allow button, which the dialog prints when it is pressed.
const GRANT: &str = "grant";

#[derive(Debug, Clone)]
pub struct DialogProcessAsker {
    executable: PathBuf,
    must_be_root_owned: bool,
}

impl DialogProcessAsker {
    pub fn installed() -> Self {
        #[cfg(debug_assertions)]
        if let Some(path) = std::env::var_os(DIALOG_OVERRIDE_VARIABLE) {
            return Self {
                executable: PathBuf::from(path),
                must_be_root_owned: false,
            };
        }
        Self {
            executable: PathBuf::from(INSTALLED_DIALOG),
            must_be_root_owned: true,
        }
    }

    /// This dialog, without the root-owned check: for tests and tools.
    pub const fn trusting(executable: PathBuf) -> Self {
        Self {
            executable,
            must_be_root_owned: false,
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
        let executable = self.executable.clone();
        Box::pin(async move {
            if !trusted {
                tracing::warn!(dialog = %executable.display(), "the consent dialog is not installed");
                return Verdict::Unreachable;
            }
            ask(&executable, &request).await
        })
    }
}

/// Runs the dialog and waits up to [`ANSWER_TIME`]; the dialog is killed when no answer came.
async fn ask(executable: &Path, request: &DialogRequest) -> Verdict {
    let spawned = Command::new(executable)
        .args(["--icon", "warning"])
        .args(["--title", &request.title(), "--message", &request.body()])
        .args(["--cancel", "Deny", "--choice"])
        .arg(format!("{GRANT}=Allow"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let child = match spawned {
        Ok(child) => child,
        Err(error) => {
            tracing::warn!(%error, "cannot start the consent dialog");
            return Verdict::Unreachable;
        }
    };
    match tokio::time::timeout(ANSWER_TIME, child.wait_with_output()).await {
        Ok(Ok(output)) if output.status.success() && last_line(&output.stdout) == Some(GRANT) => {
            Verdict::Granted
        }
        Ok(Ok(_)) | Err(_) => Verdict::Denied,
        Ok(Err(error)) => {
            tracing::warn!(%error, "the consent dialog failed");
            Verdict::Unreachable
        }
    }
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
        };
        assert!(!asker.is_trusted());
    }
}
