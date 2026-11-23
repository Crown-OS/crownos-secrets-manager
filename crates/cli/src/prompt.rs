use anyhow::{Context as _, Result};
use zeroize::Zeroizing;

/// Reads a line from the terminal without echo. It does not read standard input, so a value
/// cannot come from a pipe or sit in shell history.
pub(crate) fn hidden(prompt: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .context("reading from the terminal; this command needs an interactive terminal")
}
