//! What callers ask `crownos-secretsd` over `$XDG_RUNTIME_DIR/crownos/crownos-secrets.sock`.
//!
//! No method returns a secret value, to any caller. Agents list secrets, ask the user for a new
//! one, and ask the daemon to use one by name. The admin methods (`add`, `remove`, `bind`, `lock`,
//! `unlock`) answer only the `crownos-secrets` CLI and the Settings app. A value and the master
//! password go to the daemon through a pipe ([`transfer`]), never inside a message.

pub mod error_code;
pub mod transfer;

use secrets_core::{Binding, SecretKind, SecretName, UseOutcome};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RequestId(pub u64);

/// What a caller may know about a secret: everything but its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    pub name: SecretName,
    pub kind: SecretKind,
    pub binding: Binding,
    /// Seconds since the Unix epoch of the last permitted use since the daemon started.
    pub last_used: Option<u64>,
}

/// An agent asked the user to add a secret.
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
    /// Secrets named in `secrets.ron`.
    pub secrets: u32,
    pub pending_requests: Vec<SecretRequest>,
}

crownos_ipc::protocol! {
    /// The CrownOS secrets daemon.
    pub mod secrets: "crownos-secrets" {
        fn status() -> VaultStatus;
        fn list() -> Vec<SecretMeta>;
        /// Asks the user to add a secret that the agent needs.
        fn request(name: SecretName, kind: SecretKind, purpose: String) -> RequestId;
        /// Types the secret into a window. Not available yet: answers `UNAVAILABLE` after the
        /// access checks.
        fn type_into(name: SecretName, window: String) -> UseOutcome;
        /// Fills a login form. Not available yet.
        fn fill_login(username: String, password: SecretName, window: String) -> UseOutcome;
        /// Runs a registered command template with secrets in its environment. Not available yet.
        fn run(template: String) -> UseOutcome;
        /// Starts an HTTPS proxy session that adds the API keys to requests. Not available yet.
        fn proxy_session(names: Vec<SecretName>) -> UseOutcome;
        /// Not available yet.
        fn revoke_session(session: u64) -> UseOutcome;

        /// Admin: stores the value read from the `value` pipe.
        fn add(name: SecretName, kind: SecretKind) fds(value);
        /// Admin: returns whether the secret was there.
        fn remove(name: SecretName) -> bool;
        /// Admin: replaces the rules of a secret.
        fn bind(name: SecretName, binding: Binding);
        /// Admin.
        fn lock();
        /// Admin: unlocks with the password read from the pipe, or creates the vault.
        fn unlock() fds(master_password);

        /// A caller asked to use a secret.
        event Used { name: SecretName, actor: String, target: String, outcome: UseOutcome };
    }
}
