use std::os::fd::OwnedFd;

use anyhow::{Context as _, Result, bail};
use secrets_protocol::transfer::value_pipe;
use zeroize::Zeroizing;

/// Reads a line from the terminal without echo. It does not read standard input, so a value
/// cannot come from a pipe or sit in shell history.
pub(crate) fn hidden(prompt: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .context("reading from the terminal; this command needs an interactive terminal")
}

/// The master password, in a pipe for the daemon.
pub(crate) fn master_password() -> Result<OwnedFd> {
    let password = hidden("Master password: ")?;
    Ok(value_pipe(password.as_bytes())?)
}

/// A new master password, asked twice.
pub(crate) fn new_master_password() -> Result<OwnedFd> {
    println!("Choose a master password. Nobody can recover it.");
    let password = hidden("New master password: ")?;
    if *password != *hidden("Repeat the master password: ")? {
        bail!("the passwords are not the same");
    }
    Ok(value_pipe(password.as_bytes())?)
}
