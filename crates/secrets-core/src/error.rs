#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error(
        "a secret name has 1 to {max} characters from a-z, 0-9, '_', '.' and '-'",
        max = crate::MAX_NAME_LENGTH
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
    #[error(
        "a run template needs a command, at least one secret, a timeout of 1 to 600 seconds and an output limit of 1 to 524288 bytes"
    )]
    InvalidRunTemplate,
}
