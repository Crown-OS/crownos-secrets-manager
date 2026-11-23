use serde::Deserialize;
use serde_json::{Map, Value};

use super::results::failure;
use rmcp::model::CallToolResult;

#[derive(Deserialize)]
pub(crate) struct RequestArguments {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) purpose: String,
}

#[derive(Deserialize)]
pub(crate) struct TypeArguments {
    pub(crate) name: String,
    pub(crate) window: String,
    pub(crate) app_id: String,
    #[serde(default)]
    pub(crate) origin: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct FillLoginArguments {
    pub(crate) username_secret: String,
    pub(crate) password_secret: String,
    pub(crate) window: String,
    pub(crate) app_id: String,
    #[serde(default)]
    pub(crate) origin: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RunArguments {
    pub(crate) template: String,
    #[serde(default)]
    pub(crate) arguments: Vec<String>,
    #[serde(default)]
    pub(crate) cwd: String,
}

#[derive(Deserialize)]
pub(crate) struct HttpSessionArguments {
    pub(crate) names: Vec<String>,
    #[serde(default = "default_ttl_minutes")]
    pub(crate) ttl_minutes: u32,
}

const fn default_ttl_minutes() -> u32 {
    15
}

pub(crate) fn parse<Arguments: for<'de> Deserialize<'de>>(
    arguments: Map<String, Value>,
) -> Result<Arguments, CallToolResult> {
    serde_json::from_value(Value::Object(arguments))
        .map_err(|error| failure(format!("bad arguments: {error}")))
}
