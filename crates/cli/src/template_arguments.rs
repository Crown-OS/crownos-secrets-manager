use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use clap::Args;
use secrets_core::{RunTemplate, SecretName};

#[derive(Debug, Args)]
pub(crate) struct TemplateArguments {
    /// An environment variable from a secret, as `NAME=secret_name`.
    #[arg(long = "env")]
    environment: Vec<String>,
    /// A host the command needs. Without one, the command has no network.
    #[arg(long = "host")]
    network: Vec<String>,
    /// The working directories a caller may choose, for example `/home/me/code/*`.
    #[arg(long, default_value = "")]
    cwd_glob: String,
    #[arg(long)]
    cwd_writable: bool,
    /// Let the caller add arguments after the command.
    #[arg(long)]
    allow_arguments: bool,
    #[arg(long, default_value_t = 60)]
    timeout_seconds: u32,
    #[arg(long, default_value_t = 1024 * 1024)]
    max_output_bytes: u32,
    /// The command and its fixed arguments.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

impl TemplateArguments {
    pub(crate) fn into_template(self) -> Result<RunTemplate> {
        let environment = self
            .environment
            .iter()
            .map(|pair| {
                let (variable, secret) = pair
                    .split_once('=')
                    .with_context(|| format!("`{pair}` is not NAME=secret_name"))?;
                Ok((variable.to_owned(), SecretName::parse(secret)?))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let template = RunTemplate {
            command: self.command,
            environment,
            network: self.network,
            cwd_glob: self.cwd_glob,
            cwd_writable: self.cwd_writable,
            allow_arguments: self.allow_arguments,
            timeout_seconds: self.timeout_seconds,
            max_output_bytes: self.max_output_bytes,
        };
        template.validate()?;
        Ok(template)
    }
}
