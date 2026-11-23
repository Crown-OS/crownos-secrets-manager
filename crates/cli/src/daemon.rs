use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use crownos_ipc::Pending;
use rustix::process::{DumpableBehavior, set_dumpable_behavior};
use secrets_protocol::secrets::Client;
use serde::de::DeserializeOwned;

/// Unlock runs Argon2id, so the timeout is generous.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct Daemon {
    client: Client,
}

impl Daemon {
    /// Connects, then makes this process non-dumpable for the rest of its life. The order
    /// matters: the daemon reads who connected (`/proc/<pid>/exe`) at accept, which the kernel
    /// refuses once a process is non-dumpable. After that, no core dump and no ptrace of a
    /// process of the user can catch the master password or a value.
    pub(crate) fn connect() -> Result<Self> {
        let client = Client::connect().context(
            "cannot reach crownos-secretsd; start it with `systemctl --user start crownos-secretsd`",
        )?;
        set_dumpable_behavior(DumpableBehavior::NotDumpable)
            .context("making the process non-dumpable after it connected")?;
        Ok(Self { client })
    }

    pub(crate) fn call<Reply: DeserializeOwned>(
        &mut self,
        start: impl FnOnce(&mut Client) -> Result<Pending<Reply>, crownos_ipc::Error>,
    ) -> Result<Reply> {
        let pending = start(&mut self.client)?;
        self.client
            .wait(pending, Some(CALL_TIMEOUT))
            .map_err(|error| match error {
                crownos_ipc::Error::Remote(remote) => anyhow!(remote.message),
                other => other.into(),
            })
    }
}
