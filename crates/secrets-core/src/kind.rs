use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::CoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretKind {
    Password,
    ApiKey,
    Token,
    /// A value that a registered command gets as an environment variable.
    Env,
    Note,
    /// A user name: the only kind that is typed into a field that is not a password field.
    /// Last, because the vault encodes kinds by position.
    Username,
}

impl SecretKind {
    pub const ALL: [Self; 6] = [
        Self::Password,
        Self::ApiKey,
        Self::Token,
        Self::Env,
        Self::Note,
        Self::Username,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::ApiKey => "api-key",
            Self::Token => "token",
            Self::Env => "env",
            Self::Note => "note",
            Self::Username => "username",
        }
    }
}

impl fmt::Display for SecretKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SecretKind {
    type Err = CoreError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == text)
            .ok_or_else(|| CoreError::UnknownKind(text.to_owned()))
    }
}
