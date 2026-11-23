//! The on-screen question before a secret is used: "Allow <agent> to use the secret …?"

mod dialog_process;

use std::future::Future;
use std::pin::Pin;

use secrets_core::SecretName;

pub use dialog_process::DialogProcessAsker;

/// How long the user has to answer; no answer is a deny.
pub const ANSWER_TIME: std::time::Duration = std::time::Duration::from_secs(120);

/// One question for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogRequest {
    /// `exe:/usr/bin/...` and the like; the dialog shows it.
    pub app_key: String,
    /// The name the user knows the agent by, from the app key, never from the agent itself.
    pub agent: String,
    pub names: Vec<SecretName>,
    /// The template, the proxy hosts, or the window, app and origin.
    pub target: String,
    /// `Some(minutes)` when every secret asks once per session.
    pub session_minutes: Option<u32>,
}

impl DialogRequest {
    pub fn title(&self) -> String {
        let names: Vec<String> = self.names.iter().map(|name| format!("“{name}”")).collect();
        let noun = if self.names.len() == 1 {
            "secret"
        } else {
            "secrets"
        };
        format!(
            "Allow {} to use the {noun} {}?",
            self.agent,
            names.join(", ")
        )
    }

    pub fn body(&self) -> String {
        let remembered = self.session_minutes.map_or_else(
            || "You are asked again at the next use.".to_owned(),
            |minutes| format!("Your answer counts for {minutes} minutes."),
        );
        format!(
            "For: {}\nAgent: {}\nThe agent never sees the value. {remembered}",
            self.target, self.app_key
        )
    }
}

/// What the user said, or why there was no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Granted,
    /// A deny, or no answer within [`ANSWER_TIME`].
    Denied,
    /// No dialog could show.
    Unreachable,
}

pub type VerdictFuture = Pin<Box<dyn Future<Output = Verdict> + Send>>;

/// Shows the dialog: the consent dialog process in the session; tests give their own answers.
pub trait ConfirmationAsker: Send + Sync {
    fn ask(&self, request: DialogRequest) -> VerdictFuture;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_dialog_names_agent_secret_target_and_key() {
        let request = DialogRequest {
            app_key: "exe:/usr/bin/crownos-secrets-mcp".into(),
            agent: "crownos-secrets-mcp".into(),
            names: vec![SecretName::parse("github_token").unwrap()],
            target: "proxy to api.github.com".into(),
            session_minutes: Some(15),
        };
        assert_eq!(
            request.title(),
            "Allow crownos-secrets-mcp to use the secret “github_token”?"
        );
        assert!(request.body().contains("api.github.com"));
        assert!(request.body().contains("exe:/usr/bin/crownos-secrets-mcp"));
        assert!(request.body().contains("15 minutes"));
    }
}
