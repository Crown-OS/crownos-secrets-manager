//! `crownos-secrets-mcp`: MCP on stdin and stdout for one agent, forwarding to
//! `crownos-secretsd`. Agents use secrets by name; no tool returns a value.

mod bridge;
mod tools;

use anyhow::{Context as _, Result};
use rmcp::ServiceExt as _;
use tracing_subscriber::EnvFilter;

use crate::bridge::Bridge;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let bridge = Bridge::connect().context("reaching crownos-secretsd")?;
    let service = bridge
        .serve(rmcp::transport::stdio())
        .await
        .context("starting the MCP server")?;
    service.waiting().await.context("serving MCP")?;
    Ok(())
}
