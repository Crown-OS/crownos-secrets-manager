//! Inside a `CONNECT`: TLS from the agent with a local certificate, and verified TLS to the real
//! host.

use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{ProxyError, Shared, forward};
use secrets_core::authority::host_of;

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_1_1: &[u8] = b"http/1.1";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(crate) fn upstream_tls_config(
    roots: RootCertStore,
) -> Result<rustls::ClientConfig, ProxyError> {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![HTTP_1_1.to_vec()];
    Ok(config)
}

pub(crate) async fn serve(
    shared: Arc<Shared>,
    token: String,
    authority: String,
    upgraded: Upgraded,
) {
    if let Err(error) = serve_tunnel(shared, token, authority, upgraded).await {
        tracing::debug!(%error, "proxy tunnel ended");
    }
}

async fn serve_tunnel(
    shared: Arc<Shared>,
    token: String,
    authority: String,
    upgraded: Upgraded,
) -> Result<(), ProxyError> {
    let host = host_of(&authority).to_owned();
    let leaf = shared.authority.leaf_for(&host)?;
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(leaf.chain.clone(), leaf.private_key())?;
    server_config.alpn_protocols = vec![HTTP_1_1.to_vec()];
    let agent_side = TlsAcceptor::from(Arc::new(server_config))
        .accept(TokioIo::new(upgraded))
        .await?;

    let tcp = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(&authority))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    let server_name = ServerName::try_from(host)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let host_side = TlsConnector::from(Arc::clone(&shared.upstream_tls))
        .connect(server_name, tcp)
        .await?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(host_side))
        .await
        .map_err(std::io::Error::other)?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "upstream connection ended");
        }
    });
    let sender = Arc::new(Mutex::new(sender));
    let service = service_fn(move |request| {
        forward::forward(
            Arc::clone(&shared),
            token.clone(),
            authority.clone(),
            Arc::clone(&sender),
            request,
        )
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(agent_side), service)
        .await
        .map_err(std::io::Error::other)?;
    Ok(())
}
