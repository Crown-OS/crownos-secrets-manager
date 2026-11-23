//! `crownos-secretsd`: the one process that holds the unlocked vault. Agents ask it to use a
//! secret by name; it checks the caller, the binding, the rate limit and the lock, and writes an
//! audit line to the `crownos::audit::secrets` tracing target. No call returns a value.

mod audit;
pub mod config_store;
pub mod hardening;
pub mod identity;
pub mod server;
pub mod service;
mod util;

pub use config_store::{ConfigStore, CrownosConfigStore, MemoryConfigStore};
pub use identity::{Caller, IdentifyCaller, ProcExecutableIdentity};
pub use service::{SecretsService, ServiceError};
