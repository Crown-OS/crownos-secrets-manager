//! `crownos-secretsd`: the one process that holds the unlocked vault. Agents ask it to use a
//! secret by name; it checks the caller, the binding, the rate limit and the lock, and writes an
//! audit line to the `crownos::audit::secrets` tracing target. No call returns a value.

pub mod admin;
mod audit;
pub mod hardening;
pub mod identity;
pub mod server;
pub mod service;
mod util;

pub use identity::{Caller, IdentifyCaller, ProcExecutableIdentity};
pub use service::{SecretsService, ServiceError};
