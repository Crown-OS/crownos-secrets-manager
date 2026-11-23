//! `crownos-secretsd`: the one process that holds the unlocked vault. Agents ask it to use a
//! secret by name; it checks the caller, the binding, the rate limit and the lock, and writes an
//! audit line to the `crownos::audit::secrets` tracing target. No call returns a value.

mod audit;
pub mod confirmation;
pub mod hardening;
pub mod identity;
pub mod program_policy;
pub mod server;
pub mod service;
pub mod typing;
mod util;

pub use program_policy::ProgramPolicy;

/// The programs that may call the admin methods.
pub type AdminPolicy = ProgramPolicy;
pub use identity::{AcceptedProgramIdentity, Caller, IdentifyCaller};
pub use service::{SecretsService, ServiceError};
