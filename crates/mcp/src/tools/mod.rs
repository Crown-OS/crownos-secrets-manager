//! How each tool becomes a daemon call. None of them returns a secret value.

mod arguments;
mod catalog;
mod results;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use secrets_core::SecretKind;
use secrets_protocol::{TypingTarget, secrets};
use serde_json::{Map, Value, json};

use self::arguments::{
    FillLoginArguments, HttpSessionArguments, RequestArguments, RunArguments, TypeArguments, parse,
};
use self::results::{
    daemon_failure, failure, proxy_result, run_result, secret_name, template_name, untrusted,
    use_result,
};
use crate::bridge::Bridge;

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
            "secrets_templates" => {
                let templates = self
                    .call::<secrets::templates>(&secrets::templates {})
                    .await
                    .map_err(daemon_failure)?;
                CallToolResult::structured(json!({ "templates": templates }))
            }
            "secrets_status" => {
                let status = self
                    .call::<secrets::status>(&secrets::status {})
                    .await
                    .map_err(daemon_failure)?;
                untrusted(&json!({
                    "vault_exists": status.vault_exists,
                    "locked": status.locked,
                    "pending_requests": status.pending_requests,
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
                let TypeArguments {
                    name,
                    window,
                    app_id,
                    origin,
                } = parse(arguments)?;
                let arguments = secrets::type_into {
                    name: secret_name(name)?,
                    target: TypingTarget {
                        window,
                        app_id,
                        origin,
                    },
                };
                use_result(
                    self.call::<secrets::type_into>(&arguments)
                        .await
                        .map_err(daemon_failure)?,
                )
            }
            "secrets_fill_login" => {
                let FillLoginArguments {
                    username_secret,
                    password_secret,
                    window,
                    app_id,
                    origin,
                } = parse(arguments)?;
                let arguments = secrets::fill_login {
                    username: secret_name(username_secret)?,
                    password: secret_name(password_secret)?,
                    target: TypingTarget {
                        window,
                        app_id,
                        origin,
                    },
                };
                use_result(
                    self.call::<secrets::fill_login>(&arguments)
                        .await
                        .map_err(daemon_failure)?,
                )
            }
            "secrets_run" => {
                let RunArguments {
                    template,
                    arguments,
                    cwd,
                } = parse(arguments)?;
                let request = secrets::run {
                    template: template_name(template)?,
                    arguments,
                    cwd,
                };
                run_result(
                    self.call::<secrets::run>(&request)
                        .await
                        .map_err(daemon_failure)?,
                )
            }
            "secrets_http_session" => {
                let HttpSessionArguments { names, ttl_minutes } = parse(arguments)?;
                let names = names
                    .into_iter()
                    .map(secret_name)
                    .collect::<Result<Vec<_>, _>>()?;
                proxy_result(
                    self.call::<secrets::proxy_session>(&secrets::proxy_session {
                        names,
                        ttl_minutes,
                    })
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
            .with_instructions(catalog::INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(catalog::tools()))
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
