#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("proxy socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("the system random number generator failed")]
    Random,
}
