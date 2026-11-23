//! What callers ask `crownos-secretsd` over `$XDG_RUNTIME_DIR/crownos/crownos-secrets.sock`.
//!
//! No method returns a secret value, to any caller. Agents list secrets, ask the user for a new
//! one, and ask the daemon to use one by name. The admin methods answer only the
//! `crownos-secrets` CLI and the Settings app, and each one that changes the vault needs the
//! master password. A value and the master password go to the daemon through a pipe
//! ([`transfer`]), never inside a message.

pub mod error_code;
pub mod transfer;

use secrets_core::{
    Binding, RunTemplate, SecretKind, SecretName, TemplateName, UseOutcome, VaultSettings,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RequestId(pub u64);

/// Where a typed secret goes. computer-use fills it from the focused element: the compositor
/// window, its app id, and for a browser tab the page origin from the DevTools target URL. The
/// origin is a hint; the compositor checks the window again before it types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypingTarget {
    /// The `ext_foreign_toplevel` identifier of the window.
    pub window: String,
    pub app_id: String,
    pub origin: Option<String>,
}

/// What a caller may know about a secret: everything but its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    pub name: SecretName,
    pub kind: SecretKind,
    pub binding: Binding,
    /// Seconds since the Unix epoch of the last use since the daemon started.
    pub last_used: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateMeta {
    pub name: TemplateName,
    pub template: RunTemplate,
}

/// An agent asked the user to add a secret. `purpose` is the agent's own text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRequest {
    pub id: RequestId,
    pub name: SecretName,
    pub kind: SecretKind,
    pub purpose: String,
    pub requested_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatus {
    pub vault_exists: bool,
    pub locked: bool,
    pub locks_in_seconds: Option<u64>,
    /// The caller's own requests; an admin sees all of them.
    pub pending_requests: Vec<SecretRequest>,
}

/// The scrubbed result of a run template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunOutput {
    /// `None` when a signal ended the command.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// The output reached `max_output_bytes` and the command was stopped.
    pub truncated: bool,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunReply {
    Finished(RunOutput),
    Refused(UseOutcome),
    CwdNotAllowed,
    /// The working directory changed between the check and the start.
    CwdChanged,
    ArgumentsNotAllowed,
    /// The most runs at the same time already go on.
    TooManyRuns,
    /// `bwrap` is not installed, so nothing runs.
    SandboxMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySession {
    pub session: u64,
    /// `http://<user>:<token>@127.0.0.1:<port>`; use it as `HTTPS_PROXY`.
    pub proxy_url: String,
    /// The CA certificate to trust for this proxy, as PEM.
    pub ca_path: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxySessionReply {
    Started(ProxySession),
    Refused(UseOutcome),
    /// The secret has no HTTP binding, so the proxy has nowhere to send it.
    NoHttpBinding(SecretName),
}

crownos_ipc::protocol! {
    /// The CrownOS secrets daemon.
    pub mod secrets: "crownos-secrets" {
        fn status() -> VaultStatus;
        fn list() -> Vec<SecretMeta>;
        fn templates() -> Vec<TemplateMeta>;
        /// Asks the user to add a secret that the agent needs.
        fn request(name: SecretName, kind: SecretKind, purpose: String) -> RequestId;
        /// Types the secret into the focused field of the target window, through the compositor.
        /// `UNAVAILABLE` when the compositor does not offer `crownos_secret_input_manager_v1`.
        fn type_into(name: SecretName, target: TypingTarget) -> UseOutcome;
        /// Types the user name secret, a Tab, then the password secret into a password field;
        /// one confirmation covers both.
        fn fill_login(username: SecretName, password: SecretName, target: TypingTarget) -> UseOutcome;
        /// Runs a registered template in a sandbox with secrets in its environment.
        fn run(template: TemplateName, arguments: Vec<String>, cwd: String) -> RunReply;
        /// Starts an HTTPS proxy session that adds the API keys to requests to their hosts.
        fn proxy_session(names: Vec<SecretName>, ttl_minutes: u32) -> ProxySessionReply;
        /// Ends a proxy session of this caller. Returns whether it was open.
        fn revoke_session(session: u64) -> bool;

        /// Admin: creates the vault with the password from the pipe.
        fn init() fds(master_password);
        /// Admin.
        fn unlock() fds(master_password);
        /// Admin.
        fn lock();
        /// Admin: stores the value read from the `value` pipe.
        fn add(name: SecretName, kind: SecretKind) fds(master_password, value);
        /// Admin: returns whether the secret was there.
        fn remove(name: SecretName) fds(master_password) -> bool;
        /// Admin: replaces the rules of a secret.
        fn bind(name: SecretName, binding: Binding) fds(master_password);
        /// Admin: adds, replaces or (with `None`) removes a run template.
        fn set_template(name: TemplateName, template: Option<RunTemplate>) fds(master_password);
        /// Admin: replaces the lock time, the default confirmation and the rate limits.
        fn configure(settings: VaultSettings) fds(master_password);

        /// A caller asked to use a secret.
        event Used { name: SecretName, actor: String, target: String, outcome: UseOutcome };
    }
}
