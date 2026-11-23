//! Process settings that keep secret memory away from other same-user processes.

use rustix::process::{DumpableBehavior, set_dumpable_behavior};

/// `PR_SET_DUMPABLE=0`: no core dump, and a same-user process without `CAP_SYS_PTRACE` can no
/// longer attach with ptrace or read `/proc/<pid>/mem`.
///
/// # Errors
///
/// Fails when the kernel refuses the `prctl` call.
pub fn forbid_core_dumps_and_tracing() -> std::io::Result<()> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(Into::into)
}
