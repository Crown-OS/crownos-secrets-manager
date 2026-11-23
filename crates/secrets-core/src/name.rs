use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::CoreError;

/// The key name of a secret. Agents use this name; they never get the value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretName(String);

impl SecretName {
    pub const MAX_LENGTH: usize = 64;

    /// # Errors
    ///
    /// Fails when the name is empty, longer than [`Self::MAX_LENGTH`] or has a character outside
    /// `a-z`, `0-9`, `_`, `.` and `-`.
    pub fn parse(name: impl Into<String>) -> Result<Self, CoreError> {
        let name = name.into();
        let valid = (1..=Self::MAX_LENGTH).contains(&name.len())
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'.' | b'-')
            });
        if valid {
            Ok(Self(name))
        } else {
            Err(CoreError::InvalidName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::str::FromStr for SecretName {
    type Err = CoreError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::parse(name)
    }
}

impl Serialize for SecretName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_allowed_characters() {
        assert!(SecretName::parse("github.token_main-2").is_ok());
        assert!(SecretName::parse("a".repeat(64)).is_ok());
    }

    #[test]
    fn refuses_bad_names() {
        for name in [
            "",
            "Upper",
            "white space",
            "slash/name",
            "ü",
            &"a".repeat(65),
        ] {
            assert_eq!(
                SecretName::parse(name),
                Err(CoreError::InvalidName),
                "{name}"
            );
        }
    }

    #[test]
    fn deserializing_validates() {
        assert!(serde_json::from_str::<SecretName>("\"ok_name\"").is_ok());
        assert!(serde_json::from_str::<SecretName>("\"Bad Name\"").is_err());
        assert_eq!(
            serde_json::to_string(&SecretName::parse("x").unwrap()).unwrap(),
            "\"x\""
        );
    }
}
