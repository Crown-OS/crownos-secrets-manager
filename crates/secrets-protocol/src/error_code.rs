//! `RemoteError::code` values of the secrets daemon.

pub const UNAUTHORIZED: u32 = crownos_ipc::RemoteError::UNAUTHORIZED;
/// The method passed its checks, but this milestone does not do the work yet.
pub const UNAVAILABLE: u32 = 100;
pub const LOCKED: u32 = 101;
pub const UNKNOWN_SECRET: u32 = 102;
pub const INVALID_ARGUMENT: u32 = 103;
pub const RATE_LIMITED: u32 = 104;
pub const VAULT: u32 = 105;
