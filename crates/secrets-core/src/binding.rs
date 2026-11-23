//! Who may use a secret, and where.

use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::wildcard_matches;

/// Where a secret may go. Patterns use `*` for any run of characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// The Wayland app id of the window, for example `org.mozilla.firefox`.
    AppId(String),
    /// The web origin of the page, for example `https://*.github.com`.
    Origin(String),
}

/// When the user must confirm a use on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confirm {
    EveryUse,
    /// One confirmation covers the agent for this many minutes.
    PerSession(u32),
    Never,
}

/// How the HTTPS proxy puts an API key into a request to `host`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpBinding {
    /// A host pattern, for example `api.github.com` or `*.example.com`. With `:port`, only that
    /// port matches; without, any port.
    pub host: String,
    pub header: String,
    /// The header value, with `{value}` where the secret goes, for example `Bearer {value}`.
    pub format: String,
    /// Upper-case methods; empty allows every method.
    pub methods: Vec<String>,
    /// Path patterns, for example `/repos/*`; empty allows every path.
    pub paths: Vec<String>,
}

impl HttpBinding {
    pub const VALUE_PLACEHOLDER: &str = "{value}";

    /// Whether a CONNECT to `authority` (`host:port`) may reach this binding.
    pub fn matches_authority(&self, authority: &str) -> bool {
        if self.host.contains(':') {
            return wildcard_matches(&self.host, authority);
        }
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _port)| host);
        wildcard_matches(&self.host, host)
    }

    pub fn matches_request(&self, authority: &str, method: &str, path: &str) -> bool {
        self.matches_authority(authority)
            && (self.methods.is_empty() || self.methods.iter().any(|allowed| allowed == method))
            && (self.paths.is_empty()
                || self
                    .paths
                    .iter()
                    .any(|pattern| wildcard_matches(pattern, path)))
    }

    fn validate(&self) -> Result<(), CoreError> {
        let header_is_token = !self.header.is_empty()
            && self
                .header
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if self.host.is_empty()
            || !header_is_token
            || !self.format.contains(Self::VALUE_PLACEHOLDER)
        {
            return Err(CoreError::InvalidHttpBinding);
        }
        Ok(())
    }
}

/// The rules of one secret. The default allows nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Binding {
    /// The agents, as app keys, that may use the secret.
    pub agents: Vec<String>,
    pub targets: Vec<Target>,
    pub require_password_field: bool,
    /// `None` uses `default_confirm` from `secrets.ron`.
    pub confirm: Option<Confirm>,
    pub http: Vec<HttpBinding>,
}

impl Binding {
    /// # Errors
    ///
    /// Fails on an empty agent key, an empty target pattern or an incomplete HTTP binding.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.agents.iter().any(String::is_empty) {
            return Err(CoreError::EmptyAgent);
        }
        let empty_target = self.targets.iter().any(|target| match target {
            Target::AppId(pattern) | Target::Origin(pattern) => pattern.is_empty(),
        });
        if empty_target {
            return Err(CoreError::EmptyTarget);
        }
        self.http.iter().try_for_each(HttpBinding::validate)
    }

    pub fn allows_agent(&self, app_key: &str) -> bool {
        self.agents.iter().any(|agent| agent == app_key)
    }

    /// Whether a window with `app_id`, showing a page from `origin`, is a permitted target.
    pub fn allows_target(&self, app_id: &str, origin: Option<&str>) -> bool {
        self.targets.iter().any(|target| match target {
            Target::AppId(pattern) => wildcard_matches(pattern, app_id),
            Target::Origin(pattern) => {
                origin.is_some_and(|origin| wildcard_matches(pattern, origin))
            }
        })
    }

    pub fn confirm_or(&self, default_confirm: Confirm) -> Confirm {
        self.confirm.unwrap_or(default_confirm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_with_targets(targets: Vec<Target>) -> Binding {
        Binding {
            targets,
            ..Binding::default()
        }
    }

    #[test]
    fn the_default_binding_allows_nothing() {
        let binding = Binding::default();
        assert!(!binding.allows_agent("/usr/bin/crownos-secrets-mcp"));
        assert!(!binding.allows_target("org.mozilla.firefox", Some("https://github.com")));
    }

    #[test]
    fn targets_match_app_ids_and_origins_by_wildcard() {
        let binding = binding_with_targets(vec![
            Target::AppId("org.mozilla.*".into()),
            Target::Origin("https://*.github.com".into()),
        ]);
        assert!(binding.allows_target("org.mozilla.firefox", None));
        assert!(binding.allows_target("chromium", Some("https://api.github.com")));
        assert!(!binding.allows_target("chromium", Some("https://github.com.evil.example")));
        assert!(!binding.allows_target("chromium", None));
    }

    #[test]
    fn http_bindings_match_host_port_method_and_path() {
        let binding = HttpBinding {
            host: "*.github.com".into(),
            header: "Authorization".into(),
            format: "Bearer {value}".into(),
            methods: vec!["GET".into()],
            paths: vec!["/repos/*".into()],
        };
        assert!(binding.matches_request("api.github.com:443", "GET", "/repos/a/b"));
        assert!(!binding.matches_request("api.github.com:443", "POST", "/repos/a/b"));
        assert!(!binding.matches_request("api.github.com:443", "GET", "/user"));
        assert!(!binding.matches_request("github.com.evil.example:443", "GET", "/repos/a"));
        let with_port = HttpBinding {
            host: "localhost:8443".into(),
            ..binding
        };
        assert!(with_port.matches_authority("localhost:8443"));
        assert!(!with_port.matches_authority("localhost:9443"));
    }

    #[test]
    fn validation_refuses_incomplete_http_bindings() {
        let mut binding = Binding::default();
        binding.http.push(HttpBinding {
            host: "api.example.com".into(),
            header: "Authorization".into(),
            format: "Bearer".into(),
            methods: Vec::new(),
            paths: Vec::new(),
        });
        assert_eq!(binding.validate(), Err(CoreError::InvalidHttpBinding));
        if let Some(http) = binding.http.first_mut() {
            http.format = "Bearer {value}".into();
        }
        assert_eq!(binding.validate(), Ok(()));
    }
}
