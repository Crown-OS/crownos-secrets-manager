use std::os::fd::OwnedFd;

use anyhow::{Context as _, Result, bail};
use rustix::process::{DumpableBehavior, set_dumpable_behavior};
use secrets_protocol::transfer::value_pipe;
use zeroize::Zeroizing;

/// Reads a line from the terminal without echo. It does not read standard input, so a value
/// cannot come from a pipe or sit in shell history.
pub(crate) fn hidden(prompt: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .context("reading from the terminal; this command needs an interactive terminal")
}

/// Runs `read` with the process non-dumpable, so no core dump and no ptrace of a process of the
/// user can catch a password or a value while the CLI reads and copies it. Then the process is
/// dumpable again, because the daemon identifies the CLI through `/proc/<pid>/exe`, and the
/// kernel refuses that for a non-dumpable process. The pipe read ends stay open in this process
/// until the request goes out, so for that short time a process of the user can read the pipes
/// through `/proc/<pid>/fd`.
pub(crate) fn while_holding_secrets<Pipes>(read: impl FnOnce() -> Result<Pipes>) -> Result<Pipes> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .context("making the process non-dumpable before it reads a secret")?;
    let pipes = read();
    set_dumpable_behavior(DumpableBehavior::Dumpable)
        .context("making the process dumpable again for the daemon's caller check")?;
    pipes
}

/// The master password, in a pipe for the daemon.
pub(crate) fn master_password() -> Result<OwnedFd> {
    while_holding_secrets(|| {
        let password = hidden("Master password: ")?;
        Ok(value_pipe(password.as_bytes())?)
    })
}

/// A new master password, asked twice.
pub(crate) fn new_master_password() -> Result<OwnedFd> {
    println!("Choose a master password. Nobody can recover it.");
    while_holding_secrets(|| {
        let password = hidden("New master password: ")?;
        if *password != *hidden("Repeat the master password: ")? {
            bail!("the passwords are not the same");
        }
        Ok(value_pipe(password.as_bytes())?)
    })
}
