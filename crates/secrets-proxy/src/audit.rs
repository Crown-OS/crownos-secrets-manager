//! Audit lines of the proxy, on the same target as the daemon. Names only, never values.

const AUDIT_TARGET: &str = "crownos::audit::secrets";
const MAX_PATH_CHARACTERS: usize = 200;

pub(crate) fn connect_refused(actor: &str, authority: &str) {
    let authority = sanitized(authority);
    tracing::info!(target: AUDIT_TARGET, actor, %authority, outcome = "host-not-bound", "proxy connect");
}

pub(crate) fn request_forwarded(
    actor: &str,
    names: &str,
    authority: &str,
    method: &str,
    path: &str,
    status: u16,
) {
    let authority = sanitized(authority);
    let path = sanitized(path);
    tracing::info!(target: AUDIT_TARGET, actor, secrets = names, %authority, method, %path, status, "proxy request");
}

pub(crate) fn request_refused(actor: &str, authority: &str, reason: &str) {
    let authority = sanitized(authority);
    tracing::info!(target: AUDIT_TARGET, actor, %authority, reason, "proxy request refused");
}

fn sanitized(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(MAX_PATH_CHARACTERS)
        .collect()
}
