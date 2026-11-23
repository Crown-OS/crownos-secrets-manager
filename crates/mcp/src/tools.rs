//! The tools agents see. None of them returns a secret value, and there is no tool that could.

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use secrets_core::{SecretKind, SecretName, UseOutcome};
use secrets_protocol::{error_code, secrets};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::bridge::Bridge;

const INSTRUCTIONS: &str = "Uses the user's stored passwords, API keys and tokens by name. No \
tool returns a secret value, and none can: you name a secret and CrownOS uses it for you. Call \
secrets_list to see the names and where each may be used. If a secret you need is missing, call \
secrets_request and ask the user to add it with `crownos-secrets add <name>`; never ask the user \
to paste a secret into the chat.";

const NEVER_RETURNS_THE_VALUE: &str = "Never returns the value.";

const TOOLS: &[(&str, &str, &str)] = &[
    (
        "secrets_list",
        "The names, kinds and rules of the stored secrets. Never returns a value.",
        r#"{"type":"object","properties":{}}"#,
    ),
    (
        "secrets_status",
        "Whether the vault is locked, and the open requests. Never returns a value.",
        r#"{"type":"object","properties":{}}"#,
    ),
    (
        "secrets_request",
        "Asks the user to add a secret you need, under a name you choose (a-z, 0-9, _ . -). Say why in purpose. Never returns a value.",
        r#"{"type":"object","properties":{"name":{"type":"string"},"kind":{"type":"string","enum":["password","api-key","token","env","note"]},"purpose":{"type":"string"}},"required":["name","kind","purpose"]}"#,
    ),
    (
        "secrets_type",
        "Types a secret into the focused field of a window, after the user confirms. Not available yet. Never returns the value.",
        r#"{"type":"object","properties":{"name":{"type":"string"},"window":{"type":"string"}},"required":["name","window"]}"#,
    ),
    (
        "secrets_fill_login",
        "Fills a login form with a user name and a stored password. Not available yet. Never returns the value.",
        r#"{"type":"object","properties":{"username":{"type":"string"},"password_secret":{"type":"string"},"window":{"type":"string"}},"required":["username","password_secret","window"]}"#,
    ),
    (
        "secrets_run",
        "Runs a command template that the user registered, with secrets in its environment; output is scrubbed. Not available yet. Never returns the value.",
        r#"{"type":"object","properties":{"template":{"type":"string"}},"required":["template"]}"#,
    ),
    (
        "secrets_http_session",
        "Starts an HTTPS proxy session that adds the named API keys to requests to their bound hosts. Not available yet. Never returns the value.",
        r#"{"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}}},"required":["names"]}"#,
    ),
];

#[derive(Deserialize)]
struct RequestArguments {
    name: String,
    kind: String,
    purpose: String,
}

#[derive(Deserialize)]
struct TypeArguments {
    name: String,
    window: String,
}

#[derive(Deserialize)]
struct FillLoginArguments {
    username: String,
    password_secret: String,
    window: String,
}

#[derive(Deserialize)]
struct RunArguments {
    template: String,
}

#[derive(Deserialize)]
struct HttpSessionArguments {
    names: Vec<String>,
}

fn tool(name: &'static str, description: &'static str, schema: &str) -> Option<Tool> {
    let schema: Map<String, Value> = serde_json::from_str(schema).ok()?;
    Some(Tool::new(name, description, schema))
}

fn failure(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

fn parse<Arguments: for<'de> Deserialize<'de>>(
    arguments: Map<String, Value>,
) -> Result<Arguments, CallToolResult> {
    serde_json::from_value(Value::Object(arguments))
        .map_err(|error| failure(format!("bad arguments: {error}")))
}

fn secret_name(text: String) -> Result<SecretName, CallToolResult> {
    SecretName::parse(text).map_err(|error| failure(error.to_string()))
}

fn daemon_failure(error: crownos_ipc::Error) -> CallToolResult {
    match error {
        crownos_ipc::Error::Remote(remote) if remote.code == error_code::UNAVAILABLE => {
            failure(format!(
                "not available yet: the access checks passed, but this CrownOS release cannot use secrets this way. {NEVER_RETURNS_THE_VALUE}"
            ))
        }
        crownos_ipc::Error::Remote(remote) => failure(remote.message),
        other => failure(format!("crownos-secretsd: {other}")),
    }
}

fn use_result(outcome: UseOutcome) -> CallToolResult {
    let message = match outcome {
        UseOutcome::Done => return CallToolResult::structured(json!({ "ok": true })),
        UseOutcome::Denied => "denied: the rules of this secret do not allow you or this target",
        UseOutcome::NotPasswordField => "refused: the focused field is not a password field",
        UseOutcome::OriginMismatch => "refused: the page origin does not match the rules",
        UseOutcome::RateLimited => "slow down: too many uses this minute",
        UseOutcome::Locked => "the vault is locked; ask the user to run `crownos-secrets unlock`",
        UseOutcome::Unknown => "no stored secret has this name; see secrets_list",
    };
    failure(message)
}

impl Bridge {
    async fn call_tool_by_name(&self, name: &str, arguments: Map<String, Value>) -> CallToolResult {
        match self.try_call(name, arguments).await {
            Ok(result) | Err(result) => result,
        }
    }

    async fn try_call(
        &self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> Result<CallToolResult, CallToolResult> {
        Ok(match name {
            "secrets_list" => {
                let secrets = self
                    .call::<secrets::list>(&secrets::list {})
                    .await
                    .map_err(daemon_failure)?;
                CallToolResult::structured(json!({ "secrets": secrets }))
            }
            "secrets_status" => {
                let status = self
                    .call::<secrets::status>(&secrets::status {})
                    .await
                    .map_err(daemon_failure)?;
                CallToolResult::structured(json!({
                    "vault_exists": status.vault_exists,
                    "locked": status.locked,
                    "secrets": status.secrets,
                    "untrusted_pending_requests": status.pending_requests,
                }))
            }
            "secrets_request" => {
                let RequestArguments {
                    name,
                    kind,
                    purpose,
                } = parse(arguments)?;
                let name = secret_name(name)?;
                let kind: SecretKind = kind.parse().map_err(|error| failure(format!("{error}")))?;
                let request = secrets::request {
                    name: name.clone(),
                    kind,
                    purpose,
                };
                let id = self
                    .call::<secrets::request>(&request)
                    .await
                    .map_err(daemon_failure)?;
                CallToolResult::structured(json!({
                    "request": id.0,
                    "next_step": format!("Ask the user to run `crownos-secrets add {name} --kind {kind}` in a terminal, then `crownos-secrets bind {name} --agent <path>`."),
                }))
            }
            "secrets_type" => {
                let TypeArguments { name, window } = parse(arguments)?;
                let arguments = secrets::type_into {
                    name: secret_name(name)?,
                    window,
                };
                use_result(
                    self.call::<secrets::type_into>(&arguments)
                        .await
                        .map_err(daemon_failure)?,
                )
            }
            "secrets_fill_login" => {
                let FillLoginArguments {
                    username,
                    password_secret,
                    window,
                } = parse(arguments)?;
                let arguments = secrets::fill_login {
                    username,
                    password: secret_name(password_secret)?,
                    window,
                };
                use_result(
                    self.call::<secrets::fill_login>(&arguments)
                        .await
                        .map_err(daemon_failure)?,
                )
            }
            "secrets_run" => {
                let RunArguments { template } = parse(arguments)?;
                use_result(
                    self.call::<secrets::run>(&secrets::run { template })
                        .await
                        .map_err(daemon_failure)?,
                )
            }
            "secrets_http_session" => {
                let HttpSessionArguments { names } = parse(arguments)?;
                let names = names
                    .into_iter()
                    .map(secret_name)
                    .collect::<Result<Vec<_>, _>>()?;
                use_result(
                    self.call::<secrets::proxy_session>(&secrets::proxy_session { names })
                        .await
                        .map_err(daemon_failure)?,
                )
            }
            other => failure(format!("unknown tool `{other}`")),
        })
    }
}

impl ServerHandler for Bridge {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "crownos-secrets",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = TOOLS
            .iter()
            .filter_map(|(name, description, schema)| tool(name, description, schema))
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let arguments = request.arguments.unwrap_or_default();
        Ok(self
            .call_tool_by_name(&request.name, arguments)
            .await
            .into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_has_a_valid_schema_and_says_it_never_returns_a_value() {
        let tools: Vec<Tool> = TOOLS
            .iter()
            .filter_map(|(name, description, schema)| tool(name, description, schema))
            .collect();
        assert_eq!(tools.len(), TOOLS.len());
        for (name, description, _) in TOOLS {
            assert!(description.contains("Never returns"), "{name}");
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "{name}"
            );
        }
    }

    #[test]
    fn there_is_no_tool_that_reads_a_value() {
        for (name, _, _) in TOOLS {
            for forbidden in ["get", "read", "reveal", "show", "value", "export"] {
                assert!(!name.contains(forbidden), "{name}");
            }
        }
    }
}
