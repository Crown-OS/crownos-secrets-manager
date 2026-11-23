use anyhow::{Context as _, Result, bail};

/// The audit lines of `crownos-secretsd` from the user journal.
pub(crate) fn show(follow: bool) -> Result<()> {
    let mut journalctl = std::process::Command::new("journalctl");
    journalctl.args([
        "--user",
        "--unit=crownos-secretsd.service",
        "--output=cat",
        "--grep=crownos::audit::secrets",
        "--no-pager",
    ]);
    if follow {
        journalctl.arg("--follow");
    }
    let status = journalctl.status().context("running journalctl")?;
    if !status.success() {
        bail!("journalctl failed: {status}");
    }
    Ok(())
}
