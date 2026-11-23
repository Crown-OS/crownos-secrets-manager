//! The audit trail: one line per decision on the `crownos::audit::secrets` target. It names
//! callers and secrets, never a value.

use secrets_core::SecretName;

use crate::Caller;

pub(crate) const AUDIT_TARGET: &str = "crownos::audit::secrets";

pub(crate) fn use_decided(caller: &Caller, names: &[SecretName], target: &str, outcome: &str) {
    let names = joined(names);
    tracing::info!(target: AUDIT_TARGET, actor = %caller, secrets = %names, %target, %outcome, "use");
}

pub(crate) fn secret_requested(caller: &Caller, name: &SecretName, outcome: &str) {
    tracing::info!(target: AUDIT_TARGET, actor = %caller, secret = %name, %outcome, "request");
}

pub(crate) fn admin_call(caller: &Caller, call: &str, name: Option<&SecretName>, outcome: &str) {
    let name = name.map(SecretName::as_str).unwrap_or_default();
    tracing::info!(target: AUDIT_TARGET, actor = %caller, call, secret = %name, %outcome, "admin");
}

pub(crate) fn locked_after_timeout() {
    tracing::info!(target: AUDIT_TARGET, "vault locked after the unlock timeout");
}

fn joined(names: &[SecretName]) -> String {
    names
        .iter()
        .map(SecretName::as_str)
        .collect::<Vec<_>>()
        .join(",")
}
