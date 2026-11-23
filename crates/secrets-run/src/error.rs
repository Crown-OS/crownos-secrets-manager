#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("bubblewrap (bwrap) is not installed")]
    SandboxMissing,
    #[error("`{0}` is not a valid environment variable name")]
    InvalidVariableName(String),
    #[error("the value for `{0}` has a NUL byte, which an environment variable cannot hold")]
    ValueWithNul(String),
    #[error("a command part or argument has a NUL byte")]
    ArgumentWithNul,
    #[error("sandbox: {0}")]
    Io(#[from] std::io::Error),
}
