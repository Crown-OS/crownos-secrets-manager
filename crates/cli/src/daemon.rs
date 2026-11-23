use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use crownos_ipc::Pending;
use secrets_protocol::secrets::Client;
use secrets_protocol::transfer::value_pipe;
use serde::de::DeserializeOwned;

use crate::prompt;

/// Unlock runs Argon2id, so the timeout is generous.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct Daemon {
    client: Client,
}

impl Daemon {
    pub(crate) fn connect() -> Result<Self> {
        let client = Client::connect().context(
            "cannot reach crownos-secretsd; start it with `systemctl --user start crownos-secretsd`",
        )?;
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

    /// Asks for the master password. A missing vault is created, with the password asked twice.
    pub(crate) fn unlock(&mut self) -> Result<()> {
        let status = self.call(|client| client.status())?;
        let password = if status.vault_exists {
            prompt::hidden("Master password: ")?
        } else {
            println!("No vault exists yet. Choose a master password; it cannot be recovered.");
            let password = prompt::hidden("New master password: ")?;
            if *password != *prompt::hidden("Repeat the master password: ")? {
                bail!("the passwords are not the same");
            }
            password
        };
        let pipe = value_pipe(password.as_bytes())?;
        self.call(|client| client.unlock(pipe))
    }

    pub(crate) fn unlock_if_locked(&mut self) -> Result<()> {
        if self.call(|client| client.status())?.locked {
            self.unlock()?;
        }
        Ok(())
    }
}
