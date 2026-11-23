//! The tools agents see. Every description says that no value comes back.

use rmcp::model::Tool;
use serde_json::{Map, Value, json};

pub(crate) const INSTRUCTIONS: &str = "Uses the user's stored passwords, API keys and tokens by \
name. No tool returns a secret value, and none can: you name a secret and CrownOS uses it for \
you. Call secrets_list to see the names and where each may be used. If a secret you need is \
missing, call secrets_request and ask the user to add it with `crownos-secrets add <name>`; never \
ask the user to paste a secret into the chat.";

pub(crate) const NEVER_RETURNS_THE_VALUE: &str = "Never returns the value.";

fn tool(name: &'static str, description: &'static str, schema: Value) -> Tool {
    let schema = match schema {
        Value::Object(schema) => schema,
        _ => Map::new(),
    };
    Tool::new(name, description, schema)
}

fn no_arguments() -> Value {
    json!({ "type": "object", "properties": {} })
}

pub(crate) fn tools() -> Vec<Tool> {
    vec![
        tool(
            "secrets_list",
            "The names, kinds and rules of the stored secrets. Never returns a value.",
            no_arguments(),
        ),
        tool(
            "secrets_templates",
            "The registered command templates that secrets_run can start. Never returns a value.",
            no_arguments(),
        ),
        tool(
            "secrets_status",
            "Whether the vault is locked, and your open requests. Never returns a value.",
            no_arguments(),
        ),
        tool(
            "secrets_request",
            "Asks the user to add a secret you need, under a name you choose (a-z, 0-9, _ . -). Say why in purpose. Never returns a value.",
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "kind": { "type": "string", "enum": ["password", "api-key", "token", "env", "note"] },
                    "purpose": { "type": "string" }
                },
                "required": ["name", "kind", "purpose"]
            }),
        ),
        tool(
            "secrets_type",
            "Types a secret into the focused field of a window, after the user confirms. Not available yet. Never returns the value.",
            json!({
                "type": "object",
                "properties": { "name": { "type": "string" }, "window": { "type": "string" } },
                "required": ["name", "window"]
            }),
        ),
        tool(
            "secrets_fill_login",
            "Fills a login form with a user name and a stored password. Not available yet. Never returns the value.",
            json!({
                "type": "object",
                "properties": {
                    "username": { "type": "string" },
                    "password_secret": { "type": "string" },
                    "window": { "type": "string" }
                },
                "required": ["username", "password_secret", "window"]
            }),
        ),
        tool(
            "secrets_run",
            "Runs a registered command template in a sandbox with secrets in its environment. The output comes back with every secret scrubbed out. Never returns the value.",
            json!({
                "type": "object",
                "properties": {
                    "template": { "type": "string" },
                    "arguments": { "type": "array", "items": { "type": "string" } },
                    "cwd": { "type": "string", "description": "An absolute directory that the template allows; empty for none." }
                },
                "required": ["template"]
            }),
        ),
        tool(
            "secrets_http_session",
            "Starts an HTTPS proxy session. Requests through the proxy to a secret's bound host get the API key added by CrownOS; responses come back scrubbed. Returns the proxy URL and the CA file to trust. Never returns the value.",
            json!({
                "type": "object",
                "properties": {
                    "names": { "type": "array", "items": { "type": "string" } },
                    "ttl_minutes": { "type": "integer", "minimum": 1, "maximum": 60, "default": 15 }
                },
                "required": ["names"]
            }),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_says_it_never_returns_a_value_and_has_a_plain_name() {
        for tool in tools() {
            let description = tool.description.as_deref().unwrap_or_default();
            assert!(description.contains("Never returns"), "{}", tool.name);
            assert!(
                tool.name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "{}",
                tool.name
            );
            assert!(!tool.input_schema.is_empty(), "{}", tool.name);
        }
    }

    #[test]
    fn there_is_no_tool_that_reads_a_value() {
        for tool in tools() {
            for forbidden in ["get", "read", "reveal", "show", "value", "export"] {
                assert!(!tool.name.contains(forbidden), "{}", tool.name);
            }
        }
    }
}
