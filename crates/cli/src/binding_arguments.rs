use anyhow::{Result, bail};
use clap::Args;
use secrets_core::{Binding, Confirm, HttpBinding, Target};

#[derive(Debug, Args)]
pub(crate) struct BindingArguments {
    /// An agent that may use the secret, as the absolute path of its executable.
    #[arg(long = "agent")]
    agents: Vec<String>,
    /// A window app id where the secret may go; `*` matches any text.
    #[arg(long = "app-id")]
    app_ids: Vec<String>,
    /// A web origin where the secret may go, for example `https://*.github.com`.
    #[arg(long = "origin")]
    origins: Vec<String>,
    /// Type the secret only into a password field.
    #[arg(long)]
    require_password_field: bool,
    /// `every-use`, `never`, or `session:<minutes>`. Without it, `default_confirm` applies.
    #[arg(long, value_parser = parse_confirm)]
    confirm: Option<Confirm>,
    /// The host that gets the secret in an HTTP header.
    #[arg(long, requires_all = ["http_header", "http_format"])]
    http_host: Option<String>,
    /// The header name, for example `Authorization`.
    #[arg(long)]
    http_header: Option<String>,
    /// The header value, with `{value}` for the secret, for example `Bearer {value}`.
    #[arg(long)]
    http_format: Option<String>,
}

impl BindingArguments {
    pub(crate) fn into_binding(self) -> Result<Binding> {
        let targets = self
            .app_ids
            .into_iter()
            .map(Target::AppId)
            .chain(self.origins.into_iter().map(Target::Origin))
            .collect();
        let http = match (self.http_host, self.http_header, self.http_format) {
            (Some(host), Some(header), Some(format)) => vec![HttpBinding {
                host,
                header,
                format,
            }],
            (None, None, None) => Vec::new(),
            _ => bail!("--http-host, --http-header and --http-format go together"),
        };
        let binding = Binding {
            agents: self.agents,
            targets,
            require_password_field: self.require_password_field,
            confirm: self.confirm,
            http,
        };
        binding.validate()?;
        Ok(binding)
    }
}

fn parse_confirm(text: &str) -> Result<Confirm, String> {
    match text {
        "every-use" => Ok(Confirm::EveryUse),
        "never" => Ok(Confirm::Never),
        _ => text
            .strip_prefix("session:")
            .and_then(|minutes| minutes.parse().ok())
            .map(Confirm::PerSession)
            .ok_or_else(|| "use every-use, never or session:<minutes>".to_owned()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn confirm_values_parse() {
        assert_eq!(parse_confirm("every-use"), Ok(Confirm::EveryUse));
        assert_eq!(parse_confirm("session:15"), Ok(Confirm::PerSession(15)));
        assert!(parse_confirm("session:x").is_err());
    }
}
