#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error(
        "a secret name has 1 to {max} characters from a-z, 0-9, '_', '.' and '-'",
        max = crate::SecretName::MAX_LENGTH
    )]
    InvalidName,
    #[error("unknown secret kind `{0}`; use password, api-key, token, env or note")]
    UnknownKind(String),
    #[error("an agent key in a binding is empty")]
    EmptyAgent,
    #[error("a target pattern in a binding is empty")]
    EmptyTarget,
    #[error("an HTTP binding needs a host, a header name and a format that contains {{value}}")]
    InvalidHttpBinding,
}
