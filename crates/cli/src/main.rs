//! `crownos-secrets`: manage the secrets that agents use by name. Values go in through a hidden
//! prompt, never through arguments, and no command prints one.

mod audit;
mod binding_arguments;
mod daemon;
mod output;
mod prompt;

use anyhow::Result;
use clap::{Parser, Subcommand};
use secrets_core::{SecretKind, SecretName};
use secrets_protocol::transfer::value_pipe;

use crate::binding_arguments::BindingArguments;
use crate::daemon::Daemon;

#[derive(Debug, Parser)]
#[command(name = "crownos-secrets", about, version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Store a secret. The value is read from a hidden prompt.
    Add {
        name: SecretName,
        #[arg(long, default_value = "password")]
        kind: SecretKind,
    },
    /// Show the names, kinds and rules of the secrets.
    List,
    /// Delete a secret.
    Remove { name: SecretName },
    /// Replace the rules of a secret: which agents may use it, and where.
    Bind {
        name: SecretName,
        #[command(flatten)]
        binding: BindingArguments,
    },
    /// Forget the decrypted vault now.
    Lock,
    /// Unlock the vault with the master password, or create the vault.
    Unlock,
    /// Show whether the vault is locked, and the requests from agents.
    Status,
    /// Show the audit trail from the journal.
    Audit {
        /// Keep showing new lines.
        #[arg(long, short)]
        follow: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Add { name, kind } => {
            let mut daemon = Daemon::connect()?;
            daemon.unlock_if_locked()?;
            let value = prompt::hidden(&format!("Value for {name}: "))?;
            let pipe = value_pipe(value.as_bytes())?;
            daemon.call(|client| client.add(name.clone(), kind, pipe))?;
            println!(
                "Stored {name}. Run `crownos-secrets bind {name} --agent <path>` to let an agent use it."
            );
        }
        Command::List => {
            let secrets = Daemon::connect()?.call(|client| client.list())?;
            output::print_secrets(&secrets);
        }
        Command::Remove { name } => {
            let mut daemon = Daemon::connect()?;
            daemon.unlock_if_locked()?;
            let removed = daemon.call(|client| client.remove(name.clone()))?;
            println!(
                "{}",
                if removed {
                    "Removed."
                } else {
                    "No secret has this name."
                }
            );
        }
        Command::Bind { name, binding } => {
            let binding = binding.into_binding()?;
            let mut daemon = Daemon::connect()?;
            daemon.unlock_if_locked()?;
            daemon.call(|client| client.bind(name, binding))?;
            println!("Rules saved.");
        }
        Command::Lock => Daemon::connect()?.call(|client| client.lock())?,
        Command::Unlock => Daemon::connect()?.unlock()?,
        Command::Status => {
            let status = Daemon::connect()?.call(|client| client.status())?;
            output::print_status(&status);
        }
        Command::Audit { follow } => audit::show(follow)?,
    }
    Ok(())
}
