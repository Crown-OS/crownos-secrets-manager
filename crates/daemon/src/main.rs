use anyhow::{Context as _, Result};
use crownos_ipc::ServiceBuilder;
use crownos_secretsd::{ProcExecutableIdentity, SecretsService, admin, hardening};
use secrets_protocol::secrets;
use secrets_vault::Vault;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_ansi(false)
        .init();
    hardening::forbid_core_dumps_and_tracing().context("making the process non-dumpable")?;
    let data_directory = dirs::data_dir()
        .context("finding the data directory")?
        .join("crownos");
    let vault = Vault::new(data_directory.join("secrets.vault"));
    let service = SecretsService::new(vault, admin::admin_executables(), data_directory);
    let mut server = ServiceBuilder::new(secrets::SERVICE)
        .build()
        .context("binding the secrets socket")?;
    tracing::info!("serving {}", secrets::SERVICE);
    tokio::select! {
        served = crownos_secretsd::server::serve(&mut server, service, ProcExecutableIdentity) => {
            served.context("serving")
        }
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
