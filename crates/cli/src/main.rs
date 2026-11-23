//! `crownos-secrets`: manage the secrets that agents use by name. Values go in through a hidden
//! prompt, never through arguments, and no command prints one. Each change needs the master
//! password.

mod audit;
mod binding_arguments;
mod daemon;
mod output;
mod prompt;
mod settings_arguments;
mod template_arguments;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use rustix::process::{DumpableBehavior, set_dumpable_behavior};
use secrets_core::{SecretKind, SecretName, TemplateName};
use secrets_protocol::transfer::value_pipe;

use crate::binding_arguments::BindingArguments;
use crate::daemon::Daemon;
use crate::settings_arguments::SettingsArguments;
use crate::template_arguments::TemplateArguments;

#[derive(Debug, Parser)]
#[command(name = "crownos-secrets", about, version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the vault with a new master password.
    Init,
    /// Unlock the vault with the master password.
    Unlock,
    /// Forget the decrypted vault now.
    Lock,
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
    /// Register or replace a command template, for example
    /// `template-set gh-prs --env GH_TOKEN=github_token --host api.github.com -- gh pr list`.
    TemplateSet {
        name: TemplateName,
        #[command(flatten)]
        template: TemplateArguments,
    },
    /// Delete a command template.
    TemplateRemove { name: TemplateName },
    /// Show the command templates.
    Templates,
    /// Replace the lock time, the default confirmation and the rate limits.
    Configure {
        #[command(flatten)]
        settings: SettingsArguments,
    },
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
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .context("making the process non-dumpable before it reads a password")?;
    match Cli::parse().command {
        Command::Init => {
            let password = prompt::new_master_password()?;
            Daemon::connect()?.call(|client| client.init(password))?;
            println!("The vault is ready and unlocked.");
        }
        Command::Unlock => {
            let password = prompt::master_password()?;
            Daemon::connect()?.call(|client| client.unlock(password))?;
        }
        Command::Lock => Daemon::connect()?.call(|client| client.lock())?,
        Command::Add { name, kind } => {
            let mut daemon = Daemon::connect()?;
            let password = prompt::master_password()?;
            let value = prompt::hidden(&format!("Value for {name}: "))?;
            let value = value_pipe(value.as_bytes())?;
            daemon.call(|client| client.add(name.clone(), kind, password, value))?;
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
            let password = prompt::master_password()?;
            let removed = daemon.call(|client| client.remove(name, password))?;
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
            let password = prompt::master_password()?;
            daemon.call(|client| client.bind(name, binding, password))?;
            println!("Rules saved.");
        }
        Command::TemplateSet { name, template } => {
            let template = template.into_template()?;
            let mut daemon = Daemon::connect()?;
            let password = prompt::master_password()?;
            daemon.call(|client| client.set_template(name, Some(template), password))?;
            println!("Template saved.");
        }
        Command::TemplateRemove { name } => {
            let mut daemon = Daemon::connect()?;
            let password = prompt::master_password()?;
            daemon.call(|client| client.set_template(name, None, password))?;
            println!("Template removed.");
        }
        Command::Templates => {
            let templates = Daemon::connect()?.call(|client| client.templates())?;
            output::print_templates(&templates);
        }
        Command::Configure { settings } => {
            let mut daemon = Daemon::connect()?;
            let password = prompt::master_password()?;
            daemon.call(|client| client.configure(settings.into_settings(), password))?;
            println!("Settings saved. A new lock time counts from the next unlock.");
        }
        Command::Status => {
            let status = Daemon::connect()?.call(|client| client.status())?;
            output::print_status(&status);
        }
        Command::Audit { follow } => audit::show(follow)?,
    }
    Ok(())
}
