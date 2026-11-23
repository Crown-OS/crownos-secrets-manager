//! The shared vocabulary of the CrownOS secrets manager.
//!
//! Agents name a secret by its [`SecretName`] and never see its value. This crate holds the types
//! that every other crate uses, the [`SecretRules`] that the vault seals next to the values, and
//! the [`Scrubber`] that removes a value and its common encodings from text before a model can
//! read it.

pub mod authority;
pub mod binding;
mod error;
mod kind;
mod name;
mod outcome;
pub mod rules;
pub mod scrub;
mod util;

pub use binding::{Binding, Confirm, HttpBinding, Target};
pub use error::CoreError;
pub use kind::SecretKind;
pub use name::{MAX_NAME_LENGTH, SecretName, TemplateName};
pub use outcome::UseOutcome;
pub use rules::{
    ArgumentRefusal, RateLimitPolicy, RunTemplate, SecretEntry, SecretRules, VaultSettings,
};
pub use scrub::{ScrubStream, Scrubber};
pub use util::wildcard::wildcard_matches;

/// The largest secret value the manager accepts and stores.
pub const MAX_VALUE_BYTES: usize = 32 * 1024;
